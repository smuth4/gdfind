package main

import "errors"
import "path/filepath"
import "syscall"
import "fmt"
import "sort"
import "io/fs"
import "io"
import "os"
import "flag"
import "hash/crc64"
import "time"
import log "github.com/sirupsen/logrus"
import "github.com/cheggaaa/pb/v3"

func main() {
	var minSize, headBytes, tailBytes int64
	var ioSleep time.Duration
	var err error
	var dryRun bool
	var logLevel, action, output string
	flag.Int64Var(&minSize, "minsize", 1, "Ignore files with less than N `bytes`")
	flag.Int64Var(&headBytes, "head-bytes", 64, "Read N `bytes` from the start of files")
	flag.Int64Var(&tailBytes, "tail-bytes", 64, "Read N `bytes` from the end of files")
	flag.DurationVar(&ioSleep, "sleep", time.Duration(0), "Sleep N long between IO (default 0ms)")
	flag.StringVar(&logLevel, "level", "info", "Level to use for logs [warn,debug,info,error]")
	flag.StringVar(&action, "action", "none", "Action use for handling dupes [none,hardlink,symlink,delete]")
	flag.StringVar(&output, "output", "", "Write actions to file")
	flag.BoolVar(&dryRun, "dry-run", false, "Don't actually make any changes, just print actions")

	flag.Parse()
	switch logLevel {
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.Warnf("Unknown log level %s", logLevel)
	}
	if flag.NArg() == 0 {
		flag.Usage()
		log.Fatal("No paths provided")
		os.Exit(1)
	}
	if dryRun {
		log.Info("Running in dry run mode")
	}

	// Initial scan
	var candidates []FileInfo
	for i := 0; i < flag.NArg(); i++ {
		dirCandidates, _ := scanDir(flag.Arg(i), minSize, time.Duration(0))
		candidates = append(candidates, dirCandidates...)
		candidateLogger(candidates).Infof("Finished scanning '%s'", flag.Arg(i))
	}
	log.Infof("Found %d paths, totalling %s", len(candidates), byteToHuman(totalSize(candidates)))
	candidates, _ = removeUniqueSizes(candidates)
	candidateLogger(candidates).Infof("Removed unique sizes")
	candidates, _ = removeDuplicateInodes(candidates)
	candidateLogger(candidates).Infof("Removed duplicate inodes")

	// Sort by inode
	log.Debug("Sorting by inode")
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].inode < candidates[j].inode
	})
	candidateLogger(candidates).Info("Building head hashes")
	candidates, _ = smallHashFiles(candidates, headBytes, ioSleep)
	candidates, _ = removeDuplicateHeadHash(candidates)
	candidateLogger(candidates).Info("Removed duplicate head hashes, building tail hashes")
	candidates, err = smallHashFiles(candidates, tailBytes*-1, ioSleep)
	if err != nil {
		log.Fatal(err)
	}
	candidates, err = removeDuplicateTailHash(candidates)
	if err != nil {
		log.Fatal(err)
	}
	candidateLogger(candidates).Info("Removed duplicate tail hashes, building full hashes")
	candidates, _ = fullHashFiles(candidates, ioSleep)
	if len(candidates) == 0 {
		log.Info("No duplicates found!")
		return
	}
	hashCandidates := make(map[uint64][]FileInfo)
	for _, f := range candidates {
		hashCandidates[f.fullHash] = append(hashCandidates[f.fullHash], f)
	}
	candidates = nil // no longer needed
	var actionCandidates []FileInfo
	for _, files := range hashCandidates {
		if len(files) == 1 {
			// No dupes
			continue
		}
		log.Debugf("Path %s has %d dupe(s)", files[0].path, len(files)-1)
		for _, dupe := range files[1:] {
			actionCandidates = append(actionCandidates, dupe)
			log.Debug(dupe.path)
		}
	}
	log.Infof("Possible save of %d files, totalling %s", len(actionCandidates), byteToHuman(totalSize(actionCandidates)))
	actionCandidates = nil // Just needed the info
	switch action {
	case "none":
		// Do nothing
	case "hardlink":
		for _, files := range hashCandidates {
			if len(files) == 1 {
				// No dupes
				continue
			}
			source := files[0].path
			for _, dupe := range files[1:] {
				target := dupe.path
				if dryRun {
					fmt.Println("os.Remove('" + target + "')")
					fmt.Println("os.Link('" + source + "', '" + target + "')")
				} else {
					err = os.Remove(dupe.path)
					if err != nil {
						dupe.Logger().Errorf("Error unlinking: %s", err)
					}
					err = os.Link(files[0].path, dupe.path)
					if err != nil {
						dupe.Logger().Errorf("Error linking: %s", err)
					}
				}
			}
		}
	}
}

func candidateLogger(candidates []FileInfo) *log.Entry {
	return log.WithFields(log.Fields{"count": len(candidates), "size": byteToHuman(totalSize(candidates))})
}

func byteToHuman(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func removeDuplicateHeadHash(candidates []FileInfo) ([]FileInfo, error) {
	// Remove unique head hashes
	var headHashCount = make(map[uint64]int)
	var result []FileInfo
	for _, f := range candidates {
		headHashCount[f.headBytesHash]++
	}
	for _, f := range candidates {
		if headHashCount[f.headBytesHash] == 1 {
			f.Logger().Debug("Removing unique head hash")
		} else {
			result = append(result, f)
		}
	}
	return result, nil
}

func removeDuplicateTailHash(candidates []FileInfo) ([]FileInfo, error) {
	// Remove unique tail hashes
	var tailHashCount = make(map[uint64]int)
	var result []FileInfo
	for _, f := range candidates {
		tailHashCount[f.tailBytesHash]++
	}
	for _, f := range candidates {
		if tailHashCount[f.tailBytesHash] == 1 {
			f.Logger().Debug("Removing unique tail hash")
		} else {
			result = append(result, f)
		}
	}
	return result, nil
}

func (file FileInfo) Logger() *log.Entry {
	return log.WithFields(log.Fields{"path": file.path})
}

func fullHashFiles(candidates []FileInfo, sleep time.Duration) ([]FileInfo, error) {
	if len(candidates) == 0 {
		return candidates, nil
	}
	var result []FileInfo
	table := crc64.MakeTable(crc64.ECMA)
	bar := pb.Start64(totalSize(candidates))
	for _, f := range candidates {
		// Check if we need to even do anythong
		if f.fullHash != 0 {
			result = append(result, f)
			bar.Add64(f.size)
			continue
		}
		bar.Set("prefix", filepath.Base(f.path+" "))
		time.Sleep(sleep)
		hasher := crc64.New(table)
		handle, err := os.Open(f.path)
		defer handle.Close()
		barReader := bar.NewProxyReader(handle)
		_, err = io.Copy(hasher, barReader)
		if err != nil {
			f.Logger().Error(err)
			continue
		}
		f.fullHash = hasher.Sum64()
		result = append(result, f)
	}
	bar.Set("prefix", "")
	bar.Finish()
	return result, nil
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func smallHashFiles(candidates []FileInfo, byteLen int64, sleep time.Duration) ([]FileInfo, error) {
	// For byteLen, <0 means head, >0 means tail
	// abs(byteLen) should always be small enough that fully creating the buffer each time is fine
	if len(candidates) == 0 {
		return candidates, nil
	}
	var result []FileInfo
	bar := pb.Start64(int64(len(candidates)) * abs(byteLen))
	bar.Set(pb.Bytes, true)
	table := crc64.MakeTable(crc64.ECMA)
	if byteLen == 0 {
		return nil, errors.New("Cannot read 0 bytes")
	}
	for _, f := range candidates {
		// Check if we even need to do anything
		bar.Add64(abs(byteLen)) // This is a slight lie, we a) haven't read anything yet and b) might read less
		if (byteLen > 0 && f.headBytesHash != 0) || (byteLen < 0 && f.tailBytesHash != 0) {
			result = append(result, f)
			continue
		}
		time.Sleep(sleep)
		readSize := abs(byteLen)
		seek := int64(0)
		// Limit ourselves to readonly only the whole file
		if f.size <= readSize {
			readSize = f.size
			seek = 0
		} else if byteLen < 0 {
			// If not whole file, and we're tailing, prepare to seek
			seek = byteLen
		}
		buffer := make([]byte, readSize)
		handle, err := os.Open(f.path)
		if err != nil {
			f.Logger().Errorf("Could not open file: %s", err)
			continue
		}
		defer handle.Close()
		if seek < 0 {
			handle.Seek(seek, 2)
		}
		readTotal, err := handle.Read(buffer)
		if err != nil {
			f.Logger().Error("Could not read file: %s", err)
			continue
		}
		if int64(readTotal) != readSize {
			f.Logger().Error("Could not read full file")
		}
		// Check original param for head/tail
		if byteLen > 0 {
			f.headBytesHash = crc64.Checksum(buffer, table)
			if readSize == f.size {
				f.tailBytesHash = f.headBytesHash
				f.fullHash = f.headBytesHash
			}
		} else {
			f.tailBytesHash = crc64.Checksum(buffer, table)
			if readSize == f.size {
				f.headBytesHash = f.headBytesHash
				f.fullHash = f.headBytesHash
			}
		}
		result = append(result, f)
	}
	bar.Finish()
	return result, nil
}

func totalSize(paths []FileInfo) int64 {
	totalSize := int64(0)
	for _, f := range paths {
		totalSize += f.size
	}
	return totalSize
}

func removeDuplicateInodes(candidates []FileInfo) ([]FileInfo, error) {
	var countInodes = make(map[uint64]bool)
	var result []FileInfo
	for _, f := range candidates {
		if countInodes[f.inode] {
			f.Logger().Debug("Skipping duplicate inode")
		} else {
			countInodes[f.inode] = true
			result = append(result, f)
		}
	}
	return result, nil
}

func removeUniqueSizes(candidates []FileInfo) ([]FileInfo, error) {
	// Remove unique sizes
	var result []FileInfo
	var countSizes = make(map[int64]int)
	for _, f := range candidates {
		countSizes[f.size]++
	}
	for _, f := range candidates {
		if countSizes[f.size] == 1 {
			f.Logger().Debug("Skipping due to unique size")
		} else {
			result = append(result, f)
		}
	}
	return result, nil
}

type FileInfo struct {
	path          string
	size          int64
	inode         uint64
	headBytesHash uint64
	tailBytesHash uint64
	fullHash      uint64
	priority      int
}

func scanDir(path string, minSize int64, sleep time.Duration) ([]FileInfo, error) {
	var SkipDir error = fs.SkipDir
	var acceptedPaths []FileInfo
	var totalScanned int64
	err := filepath.WalkDir(path,
		func(subpath string, entry fs.DirEntry, err error) error {
			pathLogger := log.WithFields(log.Fields{"path": subpath})
			if err != nil {
				pathLogger.Error(err)
				return SkipDir
			}
			totalScanned++
			if entry.IsDir() {
				return nil
			}
			info, _ := entry.Info()
			if info.Size() < minSize {
				pathLogger.Debugf("Skipping file smaller than %d byte(s)", minSize)
				return nil
			}
			if info.Mode()&os.ModeSymlink != 0 {
				pathLogger.Debug("Skipping symlink")
				return nil
			}
			time.Sleep(sleep)
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				pathLogger.Error("Could not stat()")
				return nil
			}
			acceptedPaths = append(acceptedPaths, FileInfo{path: subpath, size: info.Size(), inode: stat.Ino})
			return nil
		})
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return acceptedPaths, nil
}

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
	var minSize int64
	var headBytes, tailBytes int64
	var ioSleep time.Duration
	var err error
	var logLevel string
	flag.Int64Var(&minSize, "minsize", 1, "Ignore files with less than N bytes")
	flag.Int64Var(&headBytes, "head-bytes", 64, "Read N bytes from the start of files")
	flag.Int64Var(&tailBytes, "tail-bytes", 64, "Read N bytes from the end of files")
	flag.DurationVar(&ioSleep, "sleep", time.Duration(0), "Sleep N milliseconds between IO")
	flag.StringVar(&logLevel, "level", "info", "Level to use for logs")
	switch logLevel {
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		log.Fatal("No paths provided")
		os.Exit(1)
	}

	// Initial scan
	candidates, _ := scanDir(flag.Arg(0), minSize, time.Duration(0))
	log.Infof("Found %d paths, totalling %s", len(candidates), byteToHuman(totalSize(candidates)))
	candidates, _ = removeUniqueSizes(candidates)
	candidates, _ = removeDuplicateInodes(candidates)

	// Sort by inode
	log.Debug("Sorting by inode")
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].inode < candidates[j].inode
	})
	log.Info("Building head hashes")
	candidates, _ = smallHashFiles(candidates, headBytes, ioSleep)
	candidates, _ = removeDuplicateHeadHash(candidates)
	log.Info("Building tail hashes")
	candidates, err = smallHashFiles(candidates, tailBytes*-1, ioSleep)
	if err != nil {
		log.Fatal(err)
	}
	candidates, err = removeDuplicateTailHash(candidates)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("Building full hashes")
	candidates, _ = fullHashFiles(candidates, ioSleep)
	hashCandidates := make(map[uint64][]FileInfo)
	for _, f := range candidates {
		hashCandidates[f.fullHash] = append(hashCandidates[f.fullHash], f)
	}
	candidates = nil // no longer needed
	for _, files := range hashCandidates {
		if len(files) == 1 {
			// No dupes
			continue
		}
		log.Infof("Path %s has dupes", files[0].path)
		for _, dupe := range files[1:] {
			log.Info(dupe.path)
		}
	}
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
	log.Infof("Found %d paths after unique head hash check, totalling %s", len(result), byteToHuman(totalSize(result)))
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
	log.Infof("Found %d paths after unique tail hash check, totalling %s", len(result), byteToHuman(totalSize(result)))
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
	// abs(byteLen) should always be small enough that fully creating the buffer is fine
	if len(candidates) == 0 {
		return candidates, nil
	}
	var result []FileInfo
	bar := pb.StartNew(len(candidates))
	table := crc64.MakeTable(crc64.ECMA)
	if byteLen == 0 {
		return nil, errors.New("Cannot read 0 bytes")
	}
	for _, f := range candidates {
		// Check if we even need to do anything
		bar.Increment()
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
			f.Logger().Error(err)
			continue
		}
		defer handle.Close()
		if seek < 0 {
			handle.Seek(seek, 2)
		}
		readTotal, err := handle.Read(buffer)
		if err != nil {
			f.Logger().Error(err)
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
	log.Infof("Found %d paths after duplicate inode check, totalling %s", len(result), byteToHuman(totalSize(result)))
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
	log.Infof("Found %d paths after unique size check, totalling %s", len(result), byteToHuman(totalSize(result)))
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
	log.Debugf("Scanned %d entries", totalScanned)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return acceptedPaths, nil
}

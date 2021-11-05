package main

import "errors"
import "path/filepath"
import "syscall"
import "sort"
import "io/fs"
import "io"
import "os"
import "flag"
import "hash/crc64"
import "time"
import log "github.com/sirupsen/logrus"

func main() {
	var minSize int64
	var headBytes, tailBytes int64
	var sleepInt int
	var ioSleep time.Duration
	flag.Int64Var(&minSize, "minsize", 1, "Ignore files with less than N bytes")
	flag.Int64Var(&headBytes, "head-bytes", 64, "Read N bytes from the start of files")
	flag.Int64Var(&tailBytes, "tail-bytes", 64, "Read N bytes from the end of files")
	flag.IntVar(&sleepInt, "sleep", 0, "Sleep N milliseconds between IO")
	flag.Parse()
	ioSleep = time.Duration(sleepInt) * time.Millisecond
	if flag.NArg() == 0 {
		flag.Usage()
		log.Fatal("No paths provided")
		os.Exit(1)
	}
	log.SetLevel(log.DebugLevel)

	// Initial scan
	var totalSize int64
	candidates, _ := scanDir(flag.Arg(0), minSize, ioSleep)
	for _, f := range candidates {
		totalSize += f.size
	}
	log.Infof("Found %d paths, totalling %d bytes", len(candidates), totalSize)
	candidates, _ = removeUniqueSizes(candidates)
	candidates, _ = removeDuplicateInodes(candidates)

	// Sort by inode
	log.Info("Sorting by inode")
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].inode < candidates[j].inode
	})
	log.Info("Building head hashes")
	candidates, _ = smallHashFiles(candidates, headBytes, ioSleep)
	candidates, _ = removeDuplicateHeadHash(candidates)
	log.Info("Building tail hashes")
	candidates, _ = smallHashFiles(candidates, tailBytes*-1, ioSleep)
	candidates, _ = removeDuplicateTailHash(candidates)
	log.Info("Building full hashes")
	candidates, _ = fullHashFiles(candidates)
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
	totalSize := int64(0)
	for _, f := range result {
		totalSize += f.size
	}
	log.Infof("Found %d paths after unique head hash check, totalling %d bytes", len(result), totalSize)
	return result, nil
}

func (file FileInfo) Logger() *log.Entry {
	return log.WithFields(log.Fields{"path": file.path})
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
	log.Infof("Found %d paths after unique tail hash check, totalling %d bytes", len(result), totalSize(result))
	return result, nil
}

func fullHashFiles(candidates []FileInfo) ([]FileInfo, error) {
	var result []FileInfo
	table := crc64.MakeTable(crc64.ECMA)
	for _, f := range candidates {
		// Check if we need to even do anythong
		if f.fullHash != 0 {
			continue
		}
		hasher := crc64.New(table)
		handle, err := os.Open(f.path)
		defer handle.Close()
		_, err = io.Copy(hasher, handle)
		if err != nil {
			f.Logger().Error(err)
			continue
		}
		f.fullHash = hasher.Sum64()
		result = append(result, f)
	}
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
	var result []FileInfo
	table := crc64.MakeTable(crc64.ECMA)
	if byteLen == 0 {
		return nil, errors.New("Cannot read 0 bytes")
	}
	for _, f := range candidates {
		// Check if we even need to do anything
		if (byteLen > 0 && f.headBytesHash != 0) || (byteLen < 0 && f.tailBytesHash != 0) {
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
	log.Infof("Found %d paths after duplicate inode check, totalling %d bytes", len(result), totalSize(result))
	return result, nil
}

func removeUniqueSizes(candidates []FileInfo) ([]FileInfo, error) {
	// Remove unique sizes
	var result []FileInfo
	var countSizes = make(map[int64]int)
	for _, f := range candidates {
		countSizes[f.size]++
	}
	var uniqueSizePaths []FileInfo
	for _, f := range candidates {
		if countSizes[f.size] == 1 {
			f.Logger().Debug("Skipping due to unique size")
		} else {
			result = append(result, f)
		}
	}
	log.Infof("Found %d paths after unique size check, totalling %d bytes", len(uniqueSizePaths), totalSize(result))
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

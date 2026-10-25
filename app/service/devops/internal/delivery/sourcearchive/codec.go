// Package sourcearchive owns the deterministic, provider-neutral source
// archive format shared by source fetch and archive verification adapters.
package sourcearchive

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	MediaType = "application/vnd.matrix.devops.source.v1+tar+gzip"

	MaximumArchiveBytes   = devopsv1.MaximumSourceArchiveBytes
	MaximumExpandedBytes  = devopsv1.MaximumSourceExpandedBytes
	MaximumPathCount      = devopsv1.MaximumSourcePathCount
	MaximumPathBytes      = 4 * 1024
	MaximumComponentBytes = 255

	archiveOwnerID = 65532
)

var ErrInvalid = errors.New("source archive is invalid")

var archiveModTime = time.Unix(0, 0).UTC()

type Content struct {
	ExpandedBytes int64
	PathCount     uint64
}

// Member is one validated regular file in canonical archive order. A visitor
// receives a reader bounded to exactly Size bytes and cannot reach the next
// member.
type Member struct {
	Path       string
	Executable bool
	Size       int64
}

// File is one already-authorized Git blob. Open must return that exact blob;
// Write verifies its declared size and closes it before opening the next file.
type File struct {
	Path       string
	Executable bool
	Size       int64
	Open       func() (io.ReadCloser, error)
}

func Write(ctx context.Context, destination io.Writer, files []File) (Content, error) {
	if ctx == nil || destination == nil {
		return Content{}, ErrInvalid
	}
	ordered := append([]File(nil), files...)
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].Path < ordered[right].Path
	})
	content := Content{PathCount: uint64(len(ordered))}
	if content.PathCount > MaximumPathCount {
		return Content{}, ErrInvalid
	}
	for index, file := range ordered {
		if err := ValidatePath(file.Path); err != nil || file.Open == nil || file.Size < 0 ||
			(index > 0 && ordered[index-1].Path == file.Path) ||
			file.Size > MaximumExpandedBytes-content.ExpandedBytes {
			return Content{}, ErrInvalid
		}
		content.ExpandedBytes += file.Size
	}

	gzipWriter, err := gzip.NewWriterLevel(destination, gzip.BestCompression)
	if err != nil {
		return Content{}, errors.Join(ErrInvalid, err)
	}
	gzipWriter.Header.ModTime = time.Time{}
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	for _, file := range ordered {
		if err := ctx.Err(); err != nil {
			return Content{}, err
		}
		mode := int64(0o644)
		if file.Executable {
			mode = 0o755
		}
		header := &tar.Header{
			Name: file.Path, Mode: mode, Size: file.Size, Typeflag: tar.TypeReg,
			Uid: archiveOwnerID, Gid: archiveOwnerID, ModTime: archiveModTime,
			Format: tar.FormatPAX,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return Content{}, errors.Join(ErrInvalid, err)
		}
		reader, err := file.Open()
		if err != nil || reader == nil {
			if reader != nil {
				_ = reader.Close()
			}
			return Content{}, errors.Join(ErrInvalid, err)
		}
		written, copyErr := io.CopyN(tarWriter, &contextReader{ctx: ctx, reader: reader}, file.Size)
		if copyErr != nil || written != file.Size {
			closeErr := reader.Close()
			return Content{}, errors.Join(ErrInvalid, copyErr, closeErr)
		}
		var extra [1]byte
		extraBytes, extraErr := reader.Read(extra[:])
		closeErr := reader.Close()
		if extraBytes != 0 || (extraErr != nil && !errors.Is(extraErr, io.EOF)) || closeErr != nil {
			return Content{}, errors.Join(ErrInvalid, extraErr, closeErr)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return Content{}, errors.Join(ErrInvalid, err)
	}
	if err := gzipWriter.Close(); err != nil {
		return Content{}, errors.Join(ErrInvalid, err)
	}
	return content, nil
}

func Inspect(ctx context.Context, archive io.Reader) (Content, error) {
	return consume(ctx, archive, nil)
}

// Visit validates the complete archive while handing each member to visitor.
// The visitor must consume exactly the member's bounded content before it
// returns. Archive framing, ordering, headers, limits, and trailing bytes stay
// owned by this package rather than by filesystem adapters.
func Visit(
	ctx context.Context,
	archive io.Reader,
	visitor func(Member, io.Reader) error,
) (Content, error) {
	if visitor == nil {
		return Content{}, ErrInvalid
	}
	return consume(ctx, archive, visitor)
}

func consume(
	ctx context.Context,
	archive io.Reader,
	visitor func(Member, io.Reader) error,
) (Content, error) {
	if ctx == nil || archive == nil {
		return Content{}, ErrInvalid
	}
	buffered := bufio.NewReader(&contextReader{ctx: ctx, reader: archive})
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return Content{}, ErrInvalid
	}
	gzipReader.Multistream(false)
	if !gzipReader.Header.ModTime.IsZero() || gzipReader.Header.OS != 255 ||
		gzipReader.Header.Name != "" || gzipReader.Header.Comment != "" ||
		len(gzipReader.Header.Extra) != 0 {
		_ = gzipReader.Close()
		return Content{}, ErrInvalid
	}

	tarReader := tar.NewReader(gzipReader)
	var content Content
	previousPath := ""
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil || header == nil || ctx.Err() != nil {
			_ = gzipReader.Close()
			return Content{}, ErrInvalid
		}
		if err := validateHeader(*header); err != nil ||
			(previousPath != "" && header.Name <= previousPath) ||
			content.PathCount >= MaximumPathCount || header.Size < 0 ||
			header.Size > MaximumExpandedBytes-content.ExpandedBytes {
			_ = gzipReader.Close()
			return Content{}, ErrInvalid
		}
		memberReader := &io.LimitedReader{
			R: &contextReader{ctx: ctx, reader: tarReader}, N: header.Size,
		}
		var visitErr error
		if visitor == nil {
			_, visitErr = io.Copy(io.Discard, memberReader)
		} else {
			visitErr = visitor(Member{
				Path: header.Name, Executable: header.Mode == 0o755, Size: header.Size,
			}, memberReader)
		}
		if visitErr != nil || memberReader.N != 0 || ctx.Err() != nil {
			_ = gzipReader.Close()
			return Content{}, errors.Join(ErrInvalid, visitErr)
		}
		previousPath = header.Name
		content.PathCount++
		content.ExpandedBytes += header.Size
	}
	trailingExpanded, err := io.Copy(io.Discard, gzipReader)
	if err != nil || trailingExpanded != 0 || gzipReader.Close() != nil {
		return Content{}, ErrInvalid
	}
	if _, err := buffered.Peek(1); !errors.Is(err, io.EOF) {
		return Content{}, ErrInvalid
	}
	return content, nil
}

func ValidatePath(value string) error {
	if value == "" || len(value) > MaximumPathBytes || !utf8.ValidString(value) ||
		path.IsAbs(value) || path.Clean(value) != value || strings.ContainsAny(value, "\\:") {
		return ErrInvalid
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return ErrInvalid
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." ||
			len(component) > MaximumComponentBytes || strings.EqualFold(component, ".git") {
			return ErrInvalid
		}
	}
	return nil
}

func validateHeader(header tar.Header) error {
	if err := ValidatePath(header.Name); err != nil {
		return err
	}
	if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
		return ErrInvalid
	}
	if header.Mode != 0o644 && header.Mode != 0o755 {
		return ErrInvalid
	}
	if header.Uid != archiveOwnerID || header.Gid != archiveOwnerID ||
		header.Uname != "" || header.Gname != "" || header.Linkname != "" ||
		header.Devmajor != 0 || header.Devminor != 0 ||
		!header.ModTime.Equal(archiveModTime) ||
		!header.AccessTime.IsZero() || !header.ChangeTime.IsZero() ||
		len(header.Xattrs) != 0 {
		return ErrInvalid
	}
	for key, value := range header.PAXRecords {
		if key != "path" || value != header.Name {
			return ErrInvalid
		}
	}
	if header.Format != tar.FormatUSTAR && header.Format != tar.FormatPAX {
		return fmt.Errorf("%w: unsupported tar format", ErrInvalid)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

package sourcearchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestWriteIsDeterministicAndInspectReprovesContent(t *testing.T) {
	files := []File{
		testFile("cmd/matrix/main.go", "package main\n", true),
		testFile("README.md", "matrix\n", false),
	}
	var first bytes.Buffer
	content, err := Write(context.Background(), &first, files)
	if err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	secondContent, err := Write(context.Background(), &second, []File{files[1], files[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) || content != secondContent ||
		content.PathCount != 2 || content.ExpandedBytes != int64(len("package main\n")+len("matrix\n")) {
		t.Fatalf("non-deterministic content first=%#v second=%#v", content, secondContent)
	}
	inspected, err := Inspect(context.Background(), bytes.NewReader(first.Bytes()))
	if err != nil || inspected != content {
		t.Fatalf("inspected=%#v want=%#v err=%v", inspected, content, err)
	}
}

func TestWriteRejectsUnsafeOrAmbiguousTrees(t *testing.T) {
	paths := []string{
		"", "/absolute", "../parent", "safe/../escape", "safe\\windows",
		"C:drive", ".git/config", "src/.GIT/index", "control\nname", "dir//file",
	}
	for _, filePath := range paths {
		t.Run(strings.ReplaceAll(filePath, "/", "_"), func(t *testing.T) {
			if _, err := Write(
				context.Background(), io.Discard, []File{testFile(filePath, "x", false)},
			); !errors.Is(err, ErrInvalid) {
				t.Fatalf("path %q error=%v", filePath, err)
			}
		})
	}
	duplicate := testFile("same", "x", false)
	if _, err := Write(context.Background(), io.Discard, []File{duplicate, duplicate}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate path error=%v", err)
	}
	wrongSize := testFile("short", "x", false)
	wrongSize.Size++
	if _, err := Write(context.Background(), io.Discard, []File{wrongSize}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short blob error=%v", err)
	}
}

func TestInspectRejectsArchiveAmbiguityAndUnsafeHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []tar.Header
		bodies  []string
	}{
		{
			name: "unsorted",
			headers: []tar.Header{
				testHeader("z", 0o644, tar.TypeReg, 1),
				testHeader("a", 0o644, tar.TypeReg, 1),
			},
			bodies: []string{"z", "a"},
		},
		{
			name: "symlink",
			headers: []tar.Header{
				testHeader("link", 0o777, tar.TypeSymlink, 0),
			},
			bodies: []string{""},
		},
		{
			name: "host ownership",
			headers: []tar.Header{
				testHeader("file", 0o644, tar.TypeReg, 1),
			},
			bodies: []string{"x"},
		},
	}
	tests[2].headers[0].Uname = "root"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := rawArchive(t, test.headers, test.bodies)
			if _, err := Inspect(context.Background(), bytes.NewReader(archive)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("inspect error=%v", err)
			}
		})
	}

	valid := rawArchive(
		t,
		[]tar.Header{testHeader("file", 0o644, tar.TypeReg, 1)},
		[]string{"x"},
	)
	concatenated := append(append([]byte(nil), valid...), valid...)
	if _, err := Inspect(context.Background(), bytes.NewReader(concatenated)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("concatenated gzip error=%v", err)
	}
}

func TestVisitRetainsArchiveValidationAndBoundsEachMember(t *testing.T) {
	var archive bytes.Buffer
	want := []File{
		testFile("README.md", "matrix\n", false),
		testFile("cmd/matrix/main.go", "package main\n", true),
	}
	content, err := Write(context.Background(), &archive, want)
	if err != nil {
		t.Fatal(err)
	}
	var visited []string
	got, err := Visit(
		context.Background(),
		bytes.NewReader(archive.Bytes()),
		func(member Member, body io.Reader) error {
			value, readErr := io.ReadAll(body)
			if readErr != nil {
				return readErr
			}
			visited = append(visited, member.Path+":"+string(value))
			if member.Path == "cmd/matrix/main.go" && !member.Executable {
				t.Fatal("executable bit was lost")
			}
			return nil
		},
	)
	if err != nil || got != content || !slices.Equal(
		visited,
		[]string{"README.md:matrix\n", "cmd/matrix/main.go:package main\n"},
	) {
		t.Fatalf("visited=%q content=%#v want=%#v err=%v", visited, got, content, err)
	}

	if _, err := Visit(
		context.Background(),
		bytes.NewReader(archive.Bytes()),
		func(Member, io.Reader) error { return nil },
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unconsumed member error=%v", err)
	}
	if _, err := Visit(context.Background(), bytes.NewReader(archive.Bytes()), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil visitor error=%v", err)
	}
}

func testFile(name, content string, executable bool) File {
	return File{
		Path: name, Executable: executable, Size: int64(len(content)),
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(content)), nil
		},
	}
}

func rawArchive(t *testing.T, headers []tar.Header, bodies []string) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter.Header.OS = 255
	gzipWriter.Header.ModTime = time.Time{}
	tarWriter := tar.NewWriter(gzipWriter)
	for index := range headers {
		if err := tarWriter.WriteHeader(&headers[index]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tarWriter, bodies[index]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func testHeader(name string, mode int64, kind byte, size int64) tar.Header {
	return tar.Header{
		Name: name, Mode: mode, Typeflag: kind, Size: size,
		Uid: archiveOwnerID, Gid: archiveOwnerID, ModTime: archiveModTime,
		Format: tar.FormatPAX,
	}
}

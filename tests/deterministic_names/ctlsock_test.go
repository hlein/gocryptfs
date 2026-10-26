package deterministic_names

// Integration tests for ctlsock path translation on -deterministic-names
// volumes, where missing paths fall back to a pure-computation walk.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func initDetFS(t *testing.T) (cipherDir, plainDir, sock string) {
	t.Helper()
	cipherDir = test_helpers.InitFS(t, "-deterministic-names")
	plainDir = cipherDir + ".mnt"
	sock = cipherDir + ".sock"
	test_helpers.MountOrFatal(t, cipherDir, plainDir,
		"-ctlsock="+sock, "-extpass", "echo test")
	return
}

func lastPart(p string) string {
	return p[strings.LastIndex(p, "/")+1:]
}

// findSidecar returns the single *.name file's contents under rootDir.
func findSidecar(rootDir string) (string, error) {
	var found []string
	err := filepath.WalkDir(rootDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() &&
			strings.HasPrefix(d.Name(), "gocryptfs.longname.") &&
			strings.HasSuffix(d.Name(), ".name") {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(found) != 1 {
		return "", fmt.Errorf("expected 1 .name sidecar in %s, found %d", rootDir, len(found))
	}
	data, err := os.ReadFile(found[0])
	return string(data), err
}

// TestCtlSockEncryptMissing encrypts a path that does not exist on disk.
func TestCtlSockEncryptMissing(t *testing.T) {
	_, pDir, sock := initDetFS(t)
	defer test_helpers.UnmountPanic(pDir)

	resp := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{
		EncryptPath: "no/such/file",
	})
	if resp.ErrNo != 0 || resp.Result == "" {
		t.Fatalf("EncryptPath of missing path: expected success, got %+v", resp)
	}
	if got := strings.Count(resp.Result, "/"); got != 2 {
		t.Errorf("expected 3 cipher components, got %d (%q)", got+1, resp.Result)
	}

	// Same plaintext leaf under a different parent must produce the same cipher leaf.
	resp2 := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{
		EncryptPath: "elsewhere/file",
	})
	if resp2.ErrNo != 0 {
		t.Fatalf("EncryptPath #2: %+v", resp2)
	}
	if leaf1, leaf2 := lastPart(resp.Result), lastPart(resp2.Result); leaf1 != leaf2 {
		t.Errorf("expected matching cipher leaf for same plaintext leaf, got %q vs %q",
			leaf1, leaf2)
	}
}

// TestCtlSockRoundTripMissing encrypt+decrypt round-trips a non-existent
// path. Includes a near-longnamemax-boundary component (170 bytes plaintext) to
// catch off-by-one in the short-name path.
func TestCtlSockRoundTripMissing(t *testing.T) {
	_, pDir, sock := initDetFS(t)
	defer test_helpers.UnmountPanic(pDir)

	for _, p := range []string{
		"single",
		"foo/bar/baz",
		"a/b/c/d/e/f/g",
		strings.Repeat("y", 100),
		"dir/" + strings.Repeat("z", 170),
	} {
		enc := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{EncryptPath: p})
		if enc.ErrNo != 0 {
			t.Errorf("encrypt %q: %+v", p, enc)
			continue
		}
		dec := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{DecryptPath: enc.Result})
		if dec.ErrNo != 0 {
			t.Errorf("decrypt %q (enc=%q): %+v", p, enc.Result, dec)
			continue
		}
		if dec.Result != p {
			t.Errorf("round-trip mismatch: in=%q  out=%q", p, dec.Result)
		}
	}
}

// TestCtlSockMatchesOnDisk checks that EncryptPath of an
// existing path still resolves to the real on-disk cipher tree.
func TestCtlSockMatchesOnDisk(t *testing.T) {
	cDir, pDir, sock := initDetFS(t)
	defer test_helpers.UnmountPanic(pDir)

	if err := os.MkdirAll(pDir+"/some/real/path", 0700); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"some", "some/real", "some/real/path"} {
		resp := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{EncryptPath: p})
		if resp.ErrNo != 0 {
			t.Fatalf("encrypt %q: %+v", p, resp)
		}
		if _, err := os.Stat(filepath.Join(cDir, resp.Result)); err != nil {
			t.Errorf("cipher path %q for plaintext %q not on disk under %q: %v",
				resp.Result, p, cDir, err)
		}
	}
}

// TestCtlSockExistingLongname checks that a longname token for
// an existing file is still resolved via its on-disk .name sidecar.
func TestCtlSockExistingLongname(t *testing.T) {
	_, pDir, sock := initDetFS(t)
	defer test_helpers.UnmountPanic(pDir)

	long := strings.Repeat("c", 230)
	f, err := os.Create(pDir + "/" + long)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	enc := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{EncryptPath: long})
	if enc.ErrNo != 0 {
		t.Fatalf("encrypt long: %+v", enc)
	}
	if !strings.HasPrefix(enc.Result, "gocryptfs.longname.") {
		t.Fatalf("expected longname token, got %q", enc.Result)
	}
	dec := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{DecryptPath: enc.Result})
	if dec.ErrNo != 0 {
		t.Fatalf("decrypt longname token for existing file: %+v", dec)
	}
	if dec.Result != long {
		t.Errorf("longname round-trip mismatch")
	}
}

// TestCtlSockMissingLongname checks that encrypting a path with a long-named
// leaf or intermediate dir that is not on disk yields a longname token in
// the expected position.
//
// Decryption is expected to fail with EINVAL plus a .name hint;
// TestCtlSockSidecarDecode below shows how callers recover.
func TestCtlSockMissingLongname(t *testing.T) {
	_, pDir, sock := initDetFS(t)
	defer test_helpers.UnmountPanic(pDir)

	cases := []struct {
		name      string
		plaintext string
		// index of the cipher component that should be the longname token
		longComponent int
		// total number of components in the cipher path
		numComponents int
	}{
		{"long leaf", strings.Repeat("d", 220), 0, 1},
		{"long intermediate", strings.Repeat("e", 220) + "/leaf", 0, 2},
		{"short/long/short", "head/" + strings.Repeat("f", 220) + "/tail", 1, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{EncryptPath: tc.plaintext})
			if enc.ErrNo != 0 {
				t.Fatalf("encrypt: %+v", enc)
			}
			parts := strings.Split(enc.Result, "/")
			if len(parts) != tc.numComponents {
				t.Fatalf("expected %d cipher components, got %d (%q)", tc.numComponents, len(parts), enc.Result)
			}
			if !strings.HasPrefix(parts[tc.longComponent], "gocryptfs.longname.") {
				t.Errorf("component %d should be a longname token, got %q", tc.longComponent, parts[tc.longComponent])
			}

			dec := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{DecryptPath: enc.Result})
			if dec.ErrNo != int32(syscall.EINVAL) {
				t.Errorf("decrypt missing longname: expected EINVAL, got %+v", dec)
			}
			if !strings.Contains(dec.ErrText, ".name") {
				t.Errorf("error message should mention the .name sidecar, got %q", dec.ErrText)
			}
		})
	}
}

// TestCtlSockSidecarDecode checks that passing the contents of a
// .name sidecar to DecryptPath decodes through the normal short-name path.
func TestCtlSockSidecarDecode(t *testing.T) {
	cDir, pDir, sock := initDetFS(t)
	defer test_helpers.UnmountPanic(pDir)

	long := strings.Repeat("g", 230)
	f, err := os.Create(pDir + "/" + long)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	sidecar, err := findSidecar(cDir)
	if err != nil {
		t.Fatal(err)
	}

	dec := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{DecryptPath: sidecar})
	if dec.ErrNo != 0 {
		t.Fatalf("decrypt sidecar contents: %+v", dec)
	}
	if dec.Result != long {
		t.Errorf("sidecar decrypt mismatch")
	}
}

// TestCtlSockNonDetBoundary pins the (pre-existing) ctlsock behaviour on a
// non-deterministic-names volume: missing intermediate dirs ENOENT, but a
// missing leaf under an existing parent translates fine because the on-disk
// walk never tries to Openat() the leaf.
func TestCtlSockNonDetBoundary(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	sock := cDir + ".sock"
	test_helpers.MountOrFatal(t, cDir, pDir, "-ctlsock="+sock, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(pDir)

	if err := os.Mkdir(pDir+"/existing", 0700); err != nil {
		t.Fatal(err)
	}

	// Missing intermediate -> ENOENT (unchanged).
	resp := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{EncryptPath: "missing/whatever"})
	if resp.ErrNo != int32(syscall.ENOENT) {
		t.Errorf("missing intermediate: expected ENOENT, got %+v", resp)
	}

	// Existing parent + missing leaf -> success (unchanged).
	resp = test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{EncryptPath: "existing/missing_leaf"})
	if resp.ErrNo != 0 || resp.Result == "" {
		t.Errorf("existing/missing-leaf: expected success, got %+v", resp)
	}
}

// TestCtlSockExistingLongnameMissingChild checks that a longname dir that
// exists on disk is still resolved via its .name sidecar when a path
// component below it is missing.
func TestCtlSockExistingLongnameMissingChild(t *testing.T) {
	_, pDir, sock := initDetFS(t)
	defer test_helpers.UnmountPanic(pDir)

	long := strings.Repeat("h", 230)
	if err := os.Mkdir(pDir+"/"+long, 0700); err != nil {
		t.Fatal(err)
	}

	p := long + "/missing/leaf"
	enc := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{EncryptPath: p})
	if enc.ErrNo != 0 {
		t.Fatalf("encrypt: %+v", enc)
	}
	dec := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{DecryptPath: enc.Result})
	if dec.ErrNo != 0 {
		t.Fatalf("decrypt %q: %+v", enc.Result, dec)
	}
	if dec.Result != p {
		t.Errorf("round-trip mismatch: in=%q out=%q", p, dec.Result)
	}
}

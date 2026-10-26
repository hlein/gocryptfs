package fusefrontend

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/ctlsocksrv"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var _ ctlsocksrv.Interface = &RootNode{} // Verify that interface is implemented.

// deterministicDirIV is the fixed all-zero diriv used in
// `-deterministic-names` mode (see ReadDirIVAt).
var deterministicDirIV = make([]byte, nametransform.DirIVLen)

// EncryptPath implements ctlsock.Backend
//
// Symlink-safe through openBackingDir().
//
// In `-deterministic-names` mode the result is a pure function of the
// master key and the on-disk walk is skipped, which lets the call
// succeed for paths that do not exist on disk.
func (rn *RootNode) EncryptPath(plainPath string) (cipherPath string, err error) {
	if rn.args.PlaintextNames || plainPath == "" {
		return plainPath, nil
	}
	if rn.args.DeterministicNames {
		return rn.encryptPathDeterministic(plainPath)
	}

	dirfd, _, errno := rn.prepareAtSyscallMyself()
	if errno != 0 {
		return "", errno
	}
	defer syscall.Close(dirfd)

	// Encrypt path level by level
	parts := strings.Split(plainPath, "/")
	wd := dirfd
	for i, part := range parts {
		dirIV, err := rn.nameTransform.ReadDirIVAt(wd)
		if err != nil {
			return "", err
		}
		cPart, err := rn.nameTransform.EncryptAndHashName(part, dirIV)
		if err != nil {
			return "", err
		}
		cipherPath = filepath.Join(cipherPath, cPart)
		// Last path component? We are done.
		if i == len(parts)-1 {
			break
		}
		// Descend into next directory
		wd, err = syscallcompat.Openat(wd, cPart, syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		if err != nil {
			return "", err
		}
		// Yes this is somewhat wasteful in terms of used file descriptors:
		// we keep them all open until the function returns. But it is simple
		// and reliable.
		defer syscall.Close(wd)
	}
	tlog.Debug.Printf("EncryptPath %q -> %q", plainPath, cipherPath)
	return cipherPath, nil
}

// encryptPathDeterministic encrypts plainPath without disk access.
func (rn *RootNode) encryptPathDeterministic(plainPath string) (cipherPath string, err error) {
	for _, part := range strings.Split(plainPath, "/") {
		cPart, err := rn.nameTransform.EncryptAndHashName(part, deterministicDirIV)
		if err != nil {
			return "", err
		}
		cipherPath = filepath.Join(cipherPath, cPart)
	}
	tlog.Debug.Printf("EncryptPath (deterministic) %q -> %q", plainPath, cipherPath)
	return cipherPath, nil
}

// DecryptPath implements ctlsock.Backend
//
// DecryptPath is symlink-safe because openBackingDir() and decryptPathAt()
// are symlink-safe.
//
// In `-deterministic-names` mode an ENOENT during the on-disk walk switches
// to a pure-computation walk for the remaining components, so the call
// succeeds for paths that do not exist on disk. A `gocryptfs.longname.<hash>`
// component whose `.name` file is not on disk returns EINVAL because the
// hash is one-way; the caller should pass the `.name` file contents instead.
func (rn *RootNode) DecryptPath(cipherPath string) (plainPath string, err error) {
	if rn.args.PlaintextNames || cipherPath == "" {
		return cipherPath, nil
	}

	dirfd, _, errno := rn.prepareAtSyscallMyself()
	if errno != 0 {
		return "", errno
	}
	defer syscall.Close(dirfd)

	// Decrypt path level by level
	parts := strings.Split(cipherPath, "/")
	wd := dirfd
	for i, part := range parts {
		dirIV, err := rn.nameTransform.ReadDirIVAt(wd)
		if err != nil {
			return "", err
		}
		longPart := part
		if nametransform.IsLongContent(part) {
			longPart, err = nametransform.ReadLongNameAt(wd, part)
			if err != nil {
				if rn.args.DeterministicNames && errors.Is(err, syscall.ENOENT) {
					return rn.decryptPathDeterministic(plainPath, parts[i:])
				}
				return "", err
			}
		}
		name, err := rn.nameTransform.DecryptName(longPart, dirIV)
		if err != nil {
			return "", err
		}
		plainPath = path.Join(plainPath, name)
		// Last path component? We are done.
		if i == len(parts)-1 {
			break
		}
		// Descend into next directory
		wd, err = syscallcompat.Openat(wd, part, syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		if err != nil {
			if rn.args.DeterministicNames && errors.Is(err, syscall.ENOENT) {
				return rn.decryptPathDeterministic(plainPath, parts[i+1:])
			}
			return "", err
		}
		// Yes this is somewhat wasteful in terms of used file descriptors:
		// we keep them all open until the function returns. But it is simple
		// and reliable.
		defer syscall.Close(wd)
	}
	return plainPath, nil
}

// decryptPathDeterministic continues a DecryptPath walk without disk access.
// plainPath is the already-decrypted prefix, cParts are the remaining
// ciphertext components.
func (rn *RootNode) decryptPathDeterministic(plainPath string, cParts []string) (string, error) {
	for _, part := range cParts {
		if nametransform.IsLongContent(part) {
			return "", fmt.Errorf("%q is not on disk, cannot decrypt longname %q; pass the contents of the .name file instead: %w",
				part+nametransform.LongNameSuffix, part, syscall.EINVAL)
		}
		name, err := rn.nameTransform.DecryptName(part, deterministicDirIV)
		if err != nil {
			return "", err
		}
		plainPath = path.Join(plainPath, name)
	}
	return plainPath, nil
}

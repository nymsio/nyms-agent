package keymgr

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sync"

	"github.com/nymsio/pgpmail"
	gl "github.com/op/go-logging"

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
)

const publicKeyArmorHeader = "PGP PUBLIC KEY BLOCK"
const secretKeyArmorHeader = "PGP PRIVATE KEY BLOCK"

const publicKeyringFilename = "nymskeys.pub"
const secretKeyringFilename = "nymskeys.sec"

var logger = gl.MustGetLogger("keymgr")

var nymsDirectory = ""

var defaultKeys pgpmail.KeySource

type keyStore struct {
	publicKeys openpgp.EntityList
	secretKeys openpgp.EntityList
}

func init() {
	LoadDefaultKeyring()
	defaultKeys = &keyStore{publicKeys: publicEntities, secretKeys: secretEntities}
}

func KeySource() pgpmail.KeySource {
	return defaultKeys
}

// GetPublicKey returns the best public key for the e-mail address
// specified or nil if no key is available
func (store *keyStore) GetPublicKey(address string) (*openpgp.Entity, error) {
	el := store.lookupPublicKey(address)
	if len(el) > 0 {
		return el[0], nil
	}
	return nil, nil
}

func (store *keyStore) GetAllPublicKeys(address string) (openpgp.EntityList, error) {
	return store.lookupPublicKey(address), nil
}

// GetSecret returns the best secret key for the e-mail address
// specified or nil if no key is available
func (store *keyStore) GetSecretKey(address string) (*openpgp.Entity, error) {
	el := store.lookupSecretKey(address)
	if len(el) > 0 {
		return el[0], nil
	}
	return nil, nil
}

func (store *keyStore) GetAllSecretKeys(address string) (openpgp.EntityList, error) {
	return store.lookupSecretKey(address), nil
}

func (store *keyStore) GetSecretKeyById(keyid uint64) *openpgp.Entity {
	ks := store.secretKeys.KeysById(keyid)
	if len(ks) > 0 {
		return ks[0].Entity
	}
	return nil
}

func (store *keyStore) GetPublicKeyById(keyid uint64) *openpgp.Entity {
	ks := store.publicKeys.KeysById(keyid)
	if len(ks) > 0 {
		return ks[0].Entity
	}
	return nil
}

// GetPublicKeyRing returns a list of all known public keys
func (store *keyStore) GetPublicKeyRing() openpgp.EntityList {
	return store.publicKeys
}

// GetSecretKeyRing returns a list of all known private keys
func (store *keyStore) GetSecretKeyRing() openpgp.EntityList {
	return store.secretKeys
}

func (store *keyStore) lookupPublicKey(email string) openpgp.EntityList {
	return lookupByEmail(email, store.publicKeys)
}

func (store *keyStore) lookupSecretKey(email string) openpgp.EntityList {
	return lookupByEmail(email, store.secretKeys)
}

func lookupByEmail(email string, keys openpgp.EntityList) openpgp.EntityList {
	result := []*openpgp.Entity{}
	if keys == nil {
		return result
	}
	for _, e := range keys {
		if entityMatchesEmail(email, e) {
			result = append(result, e)
		}
	}
	return result
}

func entityMatchesEmail(email string, e *openpgp.Entity) bool {
	for _, v := range e.Identities {
		if v.UserId.Email == email {
			return true
		}
	}
	return false
}

func GenerateNewKey(name, comment, email string) (*openpgp.Entity, error) {
	return generateNewKey(name, comment, email, nil)
}

func ArmorPublicKey(e *openpgp.Entity) (string, error) {
	return exportArmoredKey(e, publicKeyArmorHeader, func(w io.Writer) error {
		return e.Serialize(w)
	})
}

func ArmorSecretKey(e *openpgp.Entity) (string, error) {
	return exportArmoredKey(e, secretKeyArmorHeader, func(w io.Writer) error {
		return e.SerializePrivate(w, nil)
	})
}

func exportArmoredKey(e *openpgp.Entity, header string, writeKey func(io.Writer) error) (string, error) {
	b := &bytes.Buffer{}
	w, err := armor.Encode(b, header, map[string]string{})
	if err != nil {
		return "", err
	}
	err = writeKey(w)
	if err != nil {
		return "", err
	}
	w.Close()
	return b.String(), nil
}

func generateNewKey(name, comment, email string, config *packet.Config) (*openpgp.Entity, error) {
	e, err := openpgp.NewEntity(name, comment, email, config)
	if err != nil {
		return nil, err
	}
	addSecretKey(e)
	return e, nil
}

func addSecretKey(e *openpgp.Entity) error {
	return serializeKey(e, secretKeyringFilename, func(w io.Writer) error {
		return e.SerializePrivate(w, nil)
	})
}

func AddPublicKey(e *openpgp.Entity) error {
	return serializeKey(e, publicKeyringFilename, func(w io.Writer) error {
		return e.Serialize(w)
	})
}

func serializeKey(e *openpgp.Entity, fname string, writeKey func(io.Writer) error) error {
	lock := &sync.Mutex{}
	lock.Lock()
	defer lock.Unlock()

	path := filepath.Join(nymsDirectory, fname)
	flags := os.O_WRONLY | os.O_APPEND | os.O_CREATE

	f, err := os.OpenFile(path, flags, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := writeKey(f); err != nil {
		return err
	}
	return nil
}

func nymsPath(fname string) string {
	return filepath.Join(nymsDirectory, fname)
}

func init() {
	u, err := user.Current()
	if err != nil {
		panic(fmt.Sprintf("Failed to get current user information: %v", err))
	}
	nymsDirectory = filepath.Join(u.HomeDir, ".nyms")
	err = os.MkdirAll(nymsDirectory, 0711)
	if err != nil {
		logger.Fatalf("Error creating nyms directory (%s): %v", nymsDirectory, err)
	}
}

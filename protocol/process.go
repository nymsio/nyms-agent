package protocol

import (
	"mime"
	"strings"

	"github.com/nymsio/nyms-agent/keymgr"
	"github.com/nymsio/pgpmail"
)

func processIncomingMail(body string, result *ProcessIncomingResult, passphrase []byte) error {
	result.VerifyResult = pgpmail.VerifyNotSigned
	result.DecryptResult = pgpmail.DecryptNotEncrypted

	m, err := pgpmail.ParseMessage(body)
	if err != nil {
		return err
	}
	if !needsIncomingProcessing(m) {
		return nil
	}
	ct := getContentType(m)
	if ct == "multipart/encrypted" || isInlineEncrypted(m) {
		err = processEncrypted(m, result, passphrase)
		if err != nil {
			return err
		}
	}
	ct = getContentType(m)
	if ct == "multipart/signed" || isInlineSigned(m) {
		err = processSigned(m, result)
		if err != nil {
			return err
		}
	}
	return nil
}

func processEncrypted(m *pgpmail.Message, result *ProcessIncomingResult, passphrase []byte) error {
	status := m.DecryptWith(keymgr.KeySource(), passphrase)
	result.DecryptResult = status.Code
	result.VerifyResult = status.VerifyStatus.Code
	if status.Code == pgpmail.DecryptFailed {
		result.FailureMessage = status.FailureMessage
	} else if status.VerifyStatus.Code == pgpmail.VerifyFailed {
		result.FailureMessage = status.VerifyStatus.FailureMessage
	}
	if status.Code == pgpmail.DecryptPassphraseNeeded && status.KeyIds != nil {
		for _, id := range status.KeyIds {
			result.EncryptedKeyIds = append(result.EncryptedKeyIds, encodeKeyId(id))
		}
	}
	if status.Code == pgpmail.DecryptSuccess {
		result.EmailBody = m.String()
	}
	return nil
}

func processSigned(m *pgpmail.Message, result *ProcessIncomingResult) error {
	status := m.Verify(keymgr.KeySource())
	result.VerifyResult = status.Code
	if status.Code == pgpmail.VerifyFailed {
		result.FailureMessage = status.FailureMessage
	}
	if status.SignerKeyId != 0 {
		result.SignerKeyId = encodeKeyId(status.SignerKeyId)
	}
	return nil
}

func processOutgoingMail(body string, sign, encrypt bool, passphrase string, result *ProcessOutgoingResult) error {
	m, err := pgpmail.ParseMessage(body)
	if err != nil {
		return err
	}
	if !needsOutgoingProcessing(m) {
		return nil
	}

	if !encrypt {
		if sign {
			status := m.Sign(keymgr.KeySource(), passphrase)
			processOutgoingStatus(m, status, result)
			return nil
		}
		return nil
	}

	if sign {
		status := m.EncryptAndSign(keymgr.KeySource(), passphrase)
		processOutgoingStatus(m, status, result)
	} else {
		status := m.Encrypt(keymgr.KeySource())
		processOutgoingStatus(m, status, result)
	}
	return nil
}

func processOutgoingStatus(m *pgpmail.Message, status *pgpmail.EncryptStatus, result *ProcessOutgoingResult) {
	result.ResultCode = status.Code
	if status.Code == pgpmail.StatusFailed {
		result.FailureMessage = status.FailureMessage
	}
	if status.Code == pgpmail.StatusFailedNeedPubkeys {
		result.MissingKeyAddresses = status.MissingKeys
	}
	if status.Message != nil {
		result.EmailBody = status.Message.String()
	}
}

func needsIncomingProcessing(m *pgpmail.Message) bool {
	ct := getContentType(m)
	return ct == "multipart/encrypted" || ct == "multipart/signed" || isInlineEncrypted(m) || isInlineSigned(m)
}

func isInlineEncrypted(m *pgpmail.Message) bool {
	return strings.Contains(m.Body, "-----BEGIN PGP MESSAGE-----")
}

func isInlineSigned(m *pgpmail.Message) bool {
	return strings.Contains(m.Body, "-----BEGIN PGP SIGNED MESSAGE-----")
}

func needsOutgoingProcessing(m *pgpmail.Message) bool {
	return true
}

func getContentType(m *pgpmail.Message) string {
	ct := m.GetHeaderValue("Content-Type")
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return ""
	}
	return strings.ToLower(mt)
}

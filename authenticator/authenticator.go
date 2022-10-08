package authenticator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncbor"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/google/uuid"
)

type PublicKeyCredentialSource struct {
	Type       string        // immutable, always "public-key"
	Id         []byte        // immutable
	PrivateKey crypto.Signer // immutable
	RpId       string        // immutable
}

type Authenticator interface {
	LookupCredentialSourcebyCredentialId(id []byte) *PublicKeyCredentialSource
	MakeCredential(hash []byte, rpId string, userHandle string) ([]byte, error)
	GetAssertion(hash []byte, rpId string, allowCredentialDescriptorList []protocol.CredentialDescriptor)
}

// https://www.w3.org/TR/webauthn-2/#authenticator-credentials-map
// Maps from rpId to PublicKeyCredentialSource
type credentialsMap map[string]PublicKeyCredentialSource

// An authenticator that supports packed attestation.
type SimpleAuthenticator struct {
	AAGUID         []byte
	AttestationKey crypto.Signer
	Certificates   [][]byte // [akCert , [n * intermediate]]
	credentialsMap credentialsMap
}

func NewSimpleAuthenticator(aaguid []byte) SimpleAuthenticator {
	return SimpleAuthenticator{
		AAGUID:         aaguid,
		credentialsMap: make(credentialsMap),
	}
}

// https://www.w3.org/TR/webauthn-2/#sctn-op-lookup-credsource-by-credid
func (authenticator *SimpleAuthenticator) LookupCredentialSourceByCredentialId(id []byte) (PublicKeyCredentialSource, bool) {
	source, ok := authenticator.credentialsMap[string(id)]
	return source, ok
}

// Creates a new credential on the authenticator.  On successful completion of
// this operation, the authenticator returns the attestation object to the
// client.
//
// See https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred for more information.
func (authenticator *SimpleAuthenticator) MakeCredential(hash []byte, rpId string) ([]byte, error) {

	// TODO: excludeCredentialDescriptorList ?

	// Once the authorization gesture has been completed and user consent has been obtained, generate a new credential object

	// Let (publicKey, privateKey) be a new pair of cryptographic keys using the
	// combination of PublicKeyCredentialType and cryptographic parameters
	// represented by the first item in credTypesAndPubKeyAlgs that is supported
	// by this authenticator.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.PublicKey

	// Let userHandle be userEntity.id.

	// Let credentialSource be a new public key credential source with the fields:
	credentialSource := PublicKeyCredentialSource{
		Type:       "public-key",
		PrivateKey: privateKey,
		RpId:       rpId,
	}

	credentialId, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, err
	}
	credentialSource.Id = credentialId
	authenticator.credentialsMap[string(credentialId)] = credentialSource

	publicKeyData := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: publicKey.X.Bytes(),
		YCoord: publicKey.Y.Bytes(),
	}
	credentialPublicKey, err := webauthncbor.Marshal(publicKeyData)
	if err != nil {
		return nil, err
	}
	var credentialIdLength uint16 = uint16(len(credentialId))

	rpIdHash := sha256.Sum256([]byte(rpId))
	const signCount uint32 = 0
	rawAuthData := []byte{}

	rawAuthData = append(rawAuthData, rpIdHash[:]...)
	rawAuthData = append(rawAuthData, byte(protocol.FlagAttestedCredentialData))
	rawAuthData = binary.BigEndian.AppendUint32(rawAuthData, signCount)

	rawAuthData = append(rawAuthData, authenticator.AAGUID...)
	rawAuthData = binary.BigEndian.AppendUint16(rawAuthData, credentialIdLength)
	rawAuthData = append(rawAuthData, credentialId...)
	rawAuthData = append(rawAuthData, credentialPublicKey...)

	type packedStmt struct {
		Algorithm        webauthncose.COSEAlgorithmIdentifier `cbor:"alg"`
		Signature        []byte                               `cbor:"sig"`
		CertificateChain [][]byte                             `cbor:"x5c"`
	}

	type attestationObject struct {
		AuthData     []byte     `json:"authData"`
		Format       string     `json:"fmt"`
		AttStatement packedStmt `json:"attStmt"`
	}

	var signingKey crypto.Signer
	if authenticator.AttestationKey != nil {
		signingKey = authenticator.AttestationKey
	} else {
		signingKey = privateKey
	}

	signature, err := signingKey.Sign(rand.Reader, append(rawAuthData, hash...), crypto.SHA256)
	if err != nil {
		return nil, err
	}

	attObject := attestationObject{
		AuthData: rawAuthData,
		Format:   "packed",
		AttStatement: packedStmt{
			Algorithm:        webauthncose.AlgES256,
			Signature:        signature,
			CertificateChain: authenticator.Certificates,
		},
	}

	return webauthncbor.Marshal(&attObject)

}

type AuthenticatorAssertionResponse struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
}

func (authenticator *SimpleAuthenticator) GetAssertion(hash []byte, rpId string, allowCredentialDescriptorList []protocol.CredentialDescriptor, requireUserVerification, requireUserPresent bool) (*AuthenticatorAssertionResponse, error) {
	var credentialSource *PublicKeyCredentialSource
	for _, allowedCredential := range allowCredentialDescriptorList {
		if credentialSource, ok := authenticator.LookupCredentialSourceByCredentialId(allowedCredential.CredentialID); ok && credentialSource.Type == string(allowedCredential.Type) {
			break
		}
	}
	if credentialSource == nil {
		return nil, errors.New("no suitable credential found")
	}

	rpIdHash := sha256.Sum256([]byte(rpId))
	const signCount uint32 = 0
	rawAuthData := []byte{}

	flags := byte(0)
	if requireUserPresent {
		flags = flags | byte(protocol.FlagUserPresent)
	}
	if requireUserVerification {
		flags = flags | byte(protocol.FlagUserVerified)
	}
	rawAuthData = append(rawAuthData, rpIdHash[:]...)
	rawAuthData = append(rawAuthData, flags)
	rawAuthData = binary.BigEndian.AppendUint32(rawAuthData, signCount)

	privateKey := credentialSource.PrivateKey
	signature, err := privateKey.Sign(rand.Reader, append(rawAuthData, hash...), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &AuthenticatorAssertionResponse{
		CredentialID:      credentialSource.Id,
		AuthenticatorData: rawAuthData,
		Signature:         signature,
	}, nil

}

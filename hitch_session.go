package session

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nbio/httpcontext"
)

const (
	session_id_key      = "_ID"
	session_context_key = "SESSION"
	hash_len            = 32
)

var MalformedCookieError = errors.New("malformed cookie")
var SignatureVerificationFailedError = errors.New("signature verification failed")

// Extracts the session from the http request struct.
func GetSession(r *http.Request) Session {
	s := httpcontext.Get(r, session_context_key)
	return s.(Session)
}

// Creates a session middleware.
//
// The prefix is an optional prefix for the cookie name. The cookie name after the prefix is "_SESSION".
// The key holds the secret key to sign and verify the cookies.
// The cookie URL determines the domain and the path parts of the HTTP cookie that will be set. It can be nil.
// If the cookie URL starts with https://, then the cookie will be forced to work only on HTTPS.
// The expiresAfter sets a duration for the cookies to expire.
func HitchSession(prefix string, key SecretKey, cookieURL *url.URL, expiresAfter time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, err := readCookieFromRequest(r, prefix, key)
			if err != nil {
				log.Println(err)
			}

			httpcontext.Set(r, session_context_key, sess)

			srw := &sessionResponseWriter{
				key:          key,
				prefix:       prefix,
				r:            r,
				w:            w,
				expiresAfter: expiresAfter,
				cookieURL:    cookieURL,
			}

			next.ServeHTTP(srw, r)
			srw.WriteHeader(http.StatusOK)
		})
	}
}

// The Session type represents a session which will be stored in the session cookies.
type Session map[string]string

// Returns the session ID. If there isn't one, it generates it.
func (s Session) Id() string {
	if id, ok := s[session_id_key]; ok {
		return id
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}

	s[session_id_key] = hex.EncodeToString(buf)

	return s[session_id_key]
}

func (s Session) cookie(key SecretKey, prefix string, cookieURL *url.URL, expiresAfter time.Duration) *http.Cookie {
	buf := bytes.NewBuffer(nil)
	for k, v := range s {
		if strings.Contains(k, "\x00") {
			panic("a session key cannot contain a 0 byte")
		}
		if strings.Contains(v, "\x00") {
			panic("a session value cannot contain a 0 byte")
		}

		buf.WriteByte(0)
		buf.WriteString(k)
		buf.WriteByte(0)
		buf.WriteString(v)
	}

	data := buf.Bytes()

	cookieValue := ""

	if len(data) > 1 {
		signature := key.sign(data[1:])
		cookieValue = hex.EncodeToString(signature) + hex.EncodeToString(data)
	}

	c := &http.Cookie{
		Name:     prefix + "_SESSION",
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(expiresAfter),
	}

	if cookieURL != nil {
		c.Domain = cookieURL.Host
		c.Path = cookieURL.Path
		c.Secure = cookieURL.Scheme == "https"
	}

	return c
}

func readCookieFromRequest(r *http.Request, prefix string, key SecretKey) (Session, error) {
	sesscookie, err := r.Cookie(prefix + "_SESSION")
	if err != nil || len(sesscookie.Value) == 0 {
		if err == http.ErrNoCookie {
			err = nil
		}
		return make(Session), err
	}

	return readCookie(sesscookie.Value, key)
}

func readCookie(cookie string, key SecretKey) (Session, error) {
	b, err := hex.DecodeString(cookie)
	if err != nil {
		return make(Session), err
	}

	sess, err := readStringPairs(b, key)
	if err != nil {
		return make(Session), err
	}

	return sess, nil
}

func readStringPairs(b []byte, key SecretKey) (Session, error) {
	pieces, err := readPieces(b, key)
	if err != nil {
		return nil, err
	}
	if len(pieces)%2 == 1 {
		return nil, MalformedCookieError
	}

	sess := make(Session)

	for i := 0; i < len(pieces); i += 2 {
		sess[pieces[i]] = pieces[i+1]
	}

	return sess, nil
}

func readPieces(b []byte, key SecretKey) ([]string, error) {
	strs := []string{}
	buf := bytes.NewBuffer(nil)

	if len(b) < hash_len+1 {
		return strs, MalformedCookieError
	}

	start := hash_len + 1

	if !key.verify(b[start:], b[:start-1]) {
		return strs, SignatureVerificationFailedError
	}

	for i := start; i < len(b); i++ {
		if b[i] == 0 {
			strs = append(strs, buf.String())
			buf = bytes.NewBuffer(nil)
		} else {
			buf.WriteByte(b[i])
		}
	}

	strs = append(strs, buf.String())

	return strs, nil
}

// The key which will be used to sign and verify the cookies.
type SecretKey []byte

func (s SecretKey) sign(message []byte) []byte {
	if len(s) == 0 {
		return []byte{}
	}

	mac := hmac.New(sha256.New, s)
	mac.Write(message)
	return mac.Sum(nil)
}

func (s SecretKey) verify(message []byte, signature []byte) bool {
	return hmac.Equal([]byte(signature), []byte(s.sign(message)))
}

var _ http.ResponseWriter = &sessionResponseWriter{}

type sessionResponseWriter struct {
	key          SecretKey
	prefix       string
	r            *http.Request
	w            http.ResponseWriter
	expiresAfter time.Duration
	written      bool
	cookieURL    *url.URL
}

func (srw *sessionResponseWriter) Header() http.Header {
	return srw.w.Header()
}

func (srw *sessionResponseWriter) Write(b []byte) (int, error) {
	if !srw.written {
		srw.WriteHeader(http.StatusOK)
	}

	return srw.w.Write(b)
}

func (srw *sessionResponseWriter) WriteHeader(code int) {
	if srw.written {
		return
	}

	sess := GetSession(srw.r)
	cookie := sess.cookie(srw.key, srw.prefix, srw.cookieURL, srw.expiresAfter)
	http.SetCookie(srw.w, cookie)

	srw.w.WriteHeader(code)

	srw.written = true
}

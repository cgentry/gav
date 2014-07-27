package gav

import (
	"crypto/md5"
	"encoding/base64"
)

/**
 * 	Return the base64 of the MD5 of the body.
 *  if the body is empty, you will receive an empty string
 */
func (s * Secure) CalculateContentMD5(body []byte) string {
	var sum string = ""
	if len(body) > 0 {
		d := md5.New()
		d.Write(body)
		m5 := d.Sum(nil)
		sum = base64.StdEncoding.EncodeToString(m5)
	}
	return sum
}


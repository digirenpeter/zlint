package cabf_br

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

const cabfEccAllowedKeyUsages = "e_cabf_ecc_allowed_key_usages"

func TestCabfEccAllowedKeyUsages(t *testing.T) {
	tests := []struct {
		desc   string
		file   string
		result lint.LintStatus
	}{
		{desc: "pass - valid dv certificate with ecc key and digitalSignature", file: "valid_dv_with_ecc_key.pem", result: lint.Pass},
		{desc: "error - dv certificate with ecc key and no digitalSignature", file: "ecc_key_dv_with_no_digital_signature.pem", result: lint.Error},
		{desc: "warning - dv certificate with ecc key and keyAgreement and digitalSignature", file: "ecc_key_dv_with_key_agreement.pem", result: lint.Warn},
	}

	for _, lt := range tests {
		cert := test.ReadTestCert(lt.file)
		out := test.TestLintCert(cabfEccAllowedKeyUsages, cert, lint.Configuration{})

		if out.Status != lt.result {
			t.Errorf("%s: expected %s, got %s", lt.desc, lt.result, out.Status)
		}
	}
}

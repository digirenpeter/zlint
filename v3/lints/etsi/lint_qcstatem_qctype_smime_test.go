package etsi

/*
 * ZLint Copyright 2025 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func TestEtsiQcTypeSmime(t *testing.T) {
	m := map[string]lint.LintStatus{
		"QcStmtEtsiValidCert11.pem":         lint.NA,
		"QcStmtEtsiEsealValidCert02.pem":    lint.NA,
		"QcStmtEtsiNoQcStatmentsCert22.pem": lint.NA,
		"qcSmimeNatural.pem":                lint.Pass,
		"qcSmimeLegal.pem":                  lint.Pass,
		"qcLegal.pem":                       lint.NA,
		"qcSmimeWeb.pem":                    lint.Error,
	}
	for inputPath, expected := range m {
		out := test.TestLint("e_qcstatem_qctype_smime", inputPath)

		if out.Status != expected {
			t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
		}
	}
}

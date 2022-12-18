package oauth2

import "testing"

func Test(t *testing.T) {
	if true == false {
		t.Log("hey")
	}
	t.Fail()
}

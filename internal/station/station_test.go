package station

import "testing"

func TestParseAndRender(t *testing.T) {
	text := "prudps:/address=1.2.3.4;port=5;type=2"
	url, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if url.String() != text || url.Get("address") != "1.2.3.4" || url.Int("port") != 5 {
		t.Fatalf("parsed %s", url)
	}
	if url.Get("missing") != "" || url.Int("missing") != 0 || url.Int("address") != 0 {
		t.Fatal("the defaults are wrong")
	}
}

func TestEmptyIsAnEmptyPrudpURL(t *testing.T) {
	for _, text := range []string{"", "prudp:/"} {
		url, err := Parse(text)
		if err != nil || url.String() != "prudp:/" {
			t.Fatalf("%q gave %v, %v", text, url, err)
		}
	}
}

func TestInvalidURLs(t *testing.T) {
	for _, text := range []string{"nothing", "a:/b:/c=1", "a:/b", "a:/b=1=2", "a:/b=1;"} {
		if _, err := Parse(text); err == nil {
			t.Fatalf("%q accepted", text)
		}
	}
}

func TestSetKeepsOrderAndCopyIsIndependent(t *testing.T) {
	url, _ := Parse("prudp:/address=1;port=2")
	copied := url.Copy()
	copied.Set("address", "9")
	copied.SetInt("RVCID", 7)
	if copied.String() != "prudp:/address=9;port=2;RVCID=7" {
		t.Fatalf("copy = %s", copied)
	}
	if url.String() != "prudp:/address=1;port=2" {
		t.Fatalf("original = %s", url)
	}
}

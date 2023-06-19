package main

import (
	"errors"
	"fmt"
	"strings"
)

type SDJWT struct {
	credentialJwt string
	disclosures   []string
	bindingJwt    string
	serialized    string
}

const delimiter = "~"

func NewSDJWT(credentialJwt string, disclosures []string, bindingJwt string) *SDJWT {
	// Empty slice for nil disclosures
	if disclosures == nil {
		disclosures = []string{}
	}

	// Filtering non-empty disclosures
	filteredDisclosures := []string{}
	for _, disclosure := range disclosures {
		if disclosure != "" {
			filteredDisclosures = append(filteredDisclosures, disclosure)
		}
	}

	return &SDJWT{
		credentialJwt: credentialJwt,
		disclosures:   filteredDisclosures,
		bindingJwt:    bindingJwt,
		serialized:    serialize(credentialJwt, filteredDisclosures, bindingJwt),
	}
}

func (s *SDJWT) String() string {
	return s.serialized
}

func (s *SDJWT) GetCredentialJwt() string {
	return s.credentialJwt
}

func (s *SDJWT) GetDisclosures() []string {
	return s.disclosures
}

func (s *SDJWT) GetBindingJwt() string {
	return s.bindingJwt
}

func Parse(input string) (*SDJWT, error) {
	if input == "" {
		return nil, nil
	}

	elements := strings.Split(input, delimiter)

	// The index of the last element.
	lastIndex := len(elements) - 1

	// Make sure that all elements except the last one are not empty.
	for i := 0; i < lastIndex; i++ {
		// If the element is an empty string.
		if elements[i] == "" {
			return nil, errors.New("empty element")
		}
	}

	if len(elements) < 2 {
		return nil, fmt.Errorf("invalid element count len %d", len(elements))
	}

	// The credential JWT
	credentialJwt := elements[0]

	// The binding JWT
	bindingJwt := ""
	if !strings.HasSuffix(input, delimiter) {
		bindingJwt = elements[lastIndex]
	}

	// Disclosures
	disclosures := elements[1:lastIndex]

	return NewSDJWT(credentialJwt, disclosures, bindingJwt), nil
}

func serialize(credentialJwt string, disclosures []string, bindingJwt string) string {
	items := append([]string{credentialJwt}, disclosures...)
	if bindingJwt != "" {
		items = append(items, bindingJwt)
	}
	return strings.Join(items, delimiter)
}

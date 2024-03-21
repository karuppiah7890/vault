// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package transit

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// BatchRequestHMACItem represents a request item for batch processing.
// A map type allows us to distinguish between empty and missing values.
type batchRequestCMACItem map[string]string

// batchResponseCMACItem represents a response item for batch processing
type batchResponseCMACItem struct {
	// CMAC for the input present in the corresponding batch request item
	CMAC string `json:"cmac,omitempty" mapstructure:"cmac"`

	// Valid indicates whether signature matches the signature derived from the input string
	Valid bool `json:"valid,omitempty" mapstructure:"valid"`

	// Error, if set represents a failure encountered while encrypting a
	// corresponding batch request item
	Error string `json:"error,omitempty" mapstructure:"error"`

	// The return paths in some cases are (nil, err) and others
	// (logical.ErrorResponse(..),nil), and others (logical.ErrorResponse(..),err).
	// For batch processing to successfully mimic previous handling for simple 'input',
	// both output values are needed - though 'err' should never be serialized.
	err error

	// Reference is an arbitrary caller supplied string value that will be placed on the
	// batch response to ease correlation between inputs and outputs
	Reference string `json:"reference" mapstructure:"reference"`
}

func (b *backend) pathCMAC() *framework.Path {
	return &framework.Path{
		Pattern: "cmac/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("url_mac_length"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationVerb:   "generate",
			OperationSuffix: "cmac|cmac-with-algorithm",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use for the CMAC function",
			},

			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data",
			},

			"mac_length": {
				Type:        framework.TypeInt,
				Description: `Algorithm to use (POST body parameter). Valid values are:`,
			},

			"url_mac_length": {
				Type:        framework.TypeInt,
				Description: `Algorithm to use (POST URL parameter)`,
			},

			"key_version": {
				Type: framework.TypeInt,
				Description: `The version of the key to use for generating the CMAC.
Must be 0 (for latest) or a value greater than or equal
to the min_encryption_version configured on the key.`,
			},

			"batch_input": {
				Type: framework.TypeSlice,
				Description: `
Specifies a list of items to be processed in a single batch. When this parameter
is set, if the parameter 'input' is also set, it will be ignored.
Any batch output will preserve the order of the batch input.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCMACWrite,
			},
		},

		HelpSynopsis:    pathCMACHelpSyn,
		HelpDescription: pathCMACHelpDesc,
	}
}

func (b *backend) pathCMACWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	ver := d.Get("key_version").(int)

	return b.runWithReadLockedPolicy(ctx, req.Storage, name, func(p *keysutil.Policy) (*logical.Response, error) {
		if p.Type == keysutil.KeyType_MANAGED_KEY {
			return logical.ErrorResponse("CMAC creation is not supported with managed keys"), logical.ErrInvalidRequest
		}

		if p.Type != keysutil.KeyType_AES128_CMAC && p.Type != keysutil.KeyType_AES256_CMAC {
			return logical.ErrorResponse("key %s is not a supported CMAC key type: %s", p.Name, p.Type), logical.ErrInvalidRequest
		}

		ver, err := validateKeyVersion(p, ver)
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}

		return nil, fmt.Errorf("implement me")
	})
}

func buildCmacWriteInputBatch(d *framework.FieldData)

const pathCMACHelpSyn = `Generate a CMAC for input data using the named key`

const pathCMACHelpDesc = `
Generates a CMAC against the given input data and the named key.
`

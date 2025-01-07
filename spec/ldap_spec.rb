# frozen_string_literal: true

require "spec_helper"
require "openssl"
require "time"
require "base64"

# Implements the model defined by LDAPv3
# https://www.rfc-editor.org/rfc/rfc4511
module Ldap
  class LdapModel < RASN1::Model
    def self.model_name
      name.split("::").last.to_sym
    end
  end

  # 4.1.2.  String Types
  #        LDAPString ::= OCTET STRING -- UTF-8 encoded,
  #                                     -- [ISO10646] characters
  RASN1::Types.define_type('LdapString', from: RASN1::Types::OctetString, in_module: self)

  #        LDAPDN ::= LDAPString
  #                    -- Constrained to <distinguishedName> [RFC4514]
  RASN1::Types.define_type('LdapDN', from: LdapString, in_module: self)

  # 4.1.1.  Message Envelope
  #        MessageID ::= INTEGER (0 ..  maxInt)
  #        maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
  # TODO: Add constraint
  RASN1::Types.define_type('MessageId', from: RASN1::Types::Integer, in_module: self)

  # 4.1.10.  Referral
  #        URI ::= LDAPString     -- limited to characters permitted in
  #                                -- URIs
  RASN1::Types.define_type('LdapURI', from: LdapString, in_module: self)

  # 4.1.10.  Referral
  #        Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
  class Referral < LdapModel
    sequence_of :uri, LdapURI
  end

  # 4.1.9.  Result Message
  #
  #        LDAPResult ::= SEQUENCE {
  #              resultCode         ENUMERATED {
  #                   success                      (0),
  #                   ...
  #                   other                        (80),
  #                   ...  },
  #              matchedDN          LDAPDN,
  #              diagnosticMessage  LDAPString,
  #              referral           [3] Referral OPTIONAL }
  class LdapResult < LdapModel
    def self.components
      [
        enumerated(
          :result_code,
          enum: {
            "success" => 0,
            "operationsError" => 1,
            "protocolError" => 2,
            "timeLimitExceeded" => 3,
            "sizeLimitExceeded" => 4,
            "compareFalse" => 5,
            "compareTrue" => 6,
            "authMethodNotSupported" => 7,
            "strongerAuthRequired" => 8,
            #     -- 9 reserved --
            "referral" => 10,
            "adminLimitExceeded" => 11,
            "unavailableCriticalExtension" => 12,
            "confidentialityRequired" => 13,
            "saslBindInProgress" => 14,
            "noSuchAttribute" => 16,
            "undefinedAttributeType" => 17,
            "inappropriateMatching" => 18,
            "constraintViolation" => 19,
            "attributeOrValueExists" => 20,
            "invalidAttributeSyntax" => 21,
            #     -- 22-31 unused --
            "noSuchObject" => 32,
            "aliasProblem" => 33,
            "invalidDNSyntax" => 34,
            # -- 35 reserved for undefined isLeaf --
            "aliasDereferencingProblem" => 36,
            # -- 37-47 unused --
            "inappropriateAuthentication" => 48,
            "invalidCredentials" => 49,
            "insufficientAccessRights" => 50,
            "busy" => 51,
            "unavailable" => 52,
            "unwillingToPerform" => 53,
            "loopDetect" => 54,
            # -- 55-63 unused --
            "namingViolation" => 64,
            "objectClassViolation" => 65,
            "notAllowedOnNonLeaf" => 66,
            "notAllowedOnRDN" => 67,
            "entryAlreadyExists" => 68,
            "objectClassModsProhibited" => 69,
            #-- 70 reserved for CLDAP --
            "affectsMultipleDSAs" => 71,
            # -- 72-79 unused --
            "other" => 80
          }
        ),
        ldap_dn(:matched_dn),
        ldap_string(:diagnostic_message),
        wrapper(model(:referral, Referral), implicit: 3, optional: true)
      ]
    end

    sequence model_name, content: self.components
  end

  # 4.8.  Delete Operation
  # https://github.com/microsoft/WindowsProtocolTestSuites/blob/061e708767b42dfc085356c190f34ee3788f1180/ProtoSDK/MS-ADTS-LDAP/AdtsLdapV2Asn1Codec/DelRequest.cs
  # DelRequest ::= [APPLICATION 10] LDAPDN
  # RASN1::Types.define_type('DelRequest', from: LdapDN, in_module: self)

  class DelRequest < LdapDN
    # root_options name: 'DelRequest',
    #              class: :application,
    #              implicit: 10
  end

  # 4.1.1.  Message Envelope
  #              protocolOp      CHOICE {
  #                   bindRequest           BindRequest,
  #                   bindResponse          BindResponse,
  #                   unbindRequest         UnbindRequest,
  #                   searchRequest         SearchRequest,
  #                   searchResEntry        SearchResultEntry,
  #                   searchResDone         SearchResultDone,
  #                   searchResRef          SearchResultReference,
  #                   modifyRequest         ModifyRequest,
  #                   modifyResponse        ModifyResponse,
  #                   addRequest            AddRequest,
  #                   addResponse           AddResponse,
  #                   delRequest            DelRequest,
  #                   delResponse           DelResponse,
  #                   modDNRequest          ModifyDNRequest,
  #                   modDNResponse         ModifyDNResponse,
  #                   compareRequest        CompareRequest,
  #                   compareResponse       CompareResponse,
  #                   abandonRequest        AbandonRequest,
  #                   extendedReq           ExtendedRequest,
  #                   extendedResp          ExtendedResponse,
  #                   ...,
  #                   intermediateResponse  IntermediateResponse },
  class ProtocolOp < LdapModel
    choice model_name,
           content: [
             # TODO: DelRequest doesn't work
            #  model(:del_request, DelRequest),
            # TODO: DelRequest wrapper doesn't work
             wrapper(model(:del_request, DelRequest), implicit: 10, class: :application),
           ]
  end

  #        LDAPMessage ::= SEQUENCE {
  #              messageID       MessageID,
  #              protocolOp      CHOICE {
  #                   bindRequest           BindRequest,
  #                   bindResponse          BindResponse,
  #                   ...,
  #                   intermediateResponse  IntermediateResponse },
  #              controls       [0] Controls OPTIONAL }
  class LdapMessage < LdapModel
    sequence model_name,
            content: [
              message_id(:message_id),
              model(:protocol_op, ProtocolOp)
            ]
  end
end

# Network traffic extracted from wireshark in conjunction with:
# - https://docs.oracle.com/cd/E22289_01/html/821-1279/ldap-client-commands.html#scrolltoc
#   - ldapdelete
#   - ldapsearch
#   - ldapmodify
#   - ldapcompare
#   - ldappasswordmodify
# - https://directory.apache.org/studio/
RSpec.describe Ldap do
  describe Ldap::LdapMessage do
    # ldapdelete -H ldap://192.168.123.197 -D "Administrator@adf.local" -w 'p4$$w0rd1' uid=bjensen,ou=People,dc=example,dc=com
    context "when a DelRequest is parsed" do
      let(:valid_data) do
        Base64.decode64 <<~EOF
          MCwCAQJKJ3VpZD1iamVuc2VuLG91PVBlb3BsZSxkYz1leGFtcGxlLGRjPWNvbQ==
        EOF
      end

      # it_behaves_like "a model that produces the same binary data when to_der is called", :pending

      describe "#parse" do
        it "parses the data successfully" do
          expected = {
            LdapMessage: {
              message_id: 2,
              protocol_op: {
                del_request: 'euid=bjensen,ou=People,dc=example,dc=com'
              }
            }
          }

          # TODO: Fails on: CHOICE ProtocolOp: no type matching "J'uid=bjensen,ou=People,dc=example,dc=com"
          expect(described_class.parse(valid_data).to_h).to eq(expected)
        end
      end
    end
  end
end

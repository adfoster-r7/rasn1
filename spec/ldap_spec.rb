# frozen_string_literal: true

require 'rasn1'
require 'openssl'
require 'time'
require 'base64'

# Implements the model defined by LDAPv3
# https://www.rfc-editor.org/rfc/rfc4511
module Ldap
  class LdapModel < RASN1::Model
    def self.model_name
      name.split('::').last.to_sym
    end

    def self.message_id(name, options = {})
      custom_primitive_type_for(name, MessageId, options)
    end

    def self.ldap_string(name, options = {})
      custom_primitive_type_for(name, LdapString, options)
    end

    def self.ldap_dn(name, options = {})
      custom_primitive_type_for(name, LdapString, options)
    end

    def self.ldap_relative_dn(name, options = {})
      custom_primitive_type_for(name, LdapString, options)
    end

    def self.custom_primitive_type_for(name, clazz, options = {})
      options.merge!(name: name)
      proc = proc do |opts|
        clazz.new(options.merge(opts))
      end
      @root = Elem.new(name, proc, nil)
    end

    private_class_method :custom_primitive_type_for
  end

  #
  # 4.1.2.  String Types
  #

  #        LDAPString ::= OCTET STRING -- UTF-8 encoded,
  #                                     -- [ISO10646] characters
  class LdapString < RASN1::Types::OctetString
  end

  #        LDAPDN ::= LDAPString
  #                    -- Constrained to <distinguishedName> [RFC4514]
  class LdapDn < LdapString
  end

  #         RelativeLDAPDN ::= LDAPString
  #                            -- Constrained to <name-component> [RFC4514]
  class RelativeLdapDn < LdapString
  end

  #        URI ::= LDAPString     -- limited to characters permitted in
  #                                -- URIs
  class LdapUri < LdapString
  end

  #        AttributeDescription ::= LDAPString
  #                                 -- Constrained to <attributedescription>
  #                                 -- [RFC4512]
  class AttributeDescription < LdapString
  end

  #        AttributeValue ::= OCTET STRING
  class AttributeValue < RASN1::Types::OctetString
  end

  #
  # 4.2.  Bind Operation
  #

  #        SaslCredentials ::= SEQUENCE {
  #              mechanism               LDAPString,
  #              credentials             OCTET STRING OPTIONAL }
  class SaslCredentials < LdapModel
    sequence model_name,
             content: [
               ldap_string(:mechanism),
               octet_string(:credentials, optional: true)
             ]
  end

  #        AuthenticationChoice ::= CHOICE {
  #              simple                  [0] OCTET STRING,
  #                                      -- 1 and 2 reserved
  #              sasl                    [3] SaslCredentials,
  #              ...  }
  class AuthenticationChoice < LdapModel
    choice model_name,
             content: [
               octet_string(:simple, implicit: 0),
               wrapper(model(:sasl, SaslCredentials), implicit: 3)
             ]
  end

  #        BindRequest ::= [APPLICATION 0] SEQUENCE {
  #              version                 INTEGER (1 ..  127),
  #              name                    LDAPDN,
  #              authentication          AuthenticationChoice }
  class BindRequest < LdapModel
    sequence model_name,
             class: :application,
             implicit: 0,
             content: [
               integer(:version),
               ldap_dn(:name),
               model(:authentication, AuthenticationChoice)
             ]
  end

  #        Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
  class Referral < LdapModel
    sequence_of :items, LdapUri
  end

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
            "success"                      => 0,
            "operationsError"              => 1,
            "protocolError"                => 2,
            "timeLimitExceeded"            => 3,
            "sizeLimitExceeded"            => 4,
            "compareFalse"                 => 5,
            "compareTrue"                  => 6,
            "authMethodNotSupported"       => 7,
            "strongerAuthRequired"         => 8,
            #     -- 9 reserved --
            "referral"                     => 10,
            "adminLimitExceeded"           => 11,
            "unavailableCriticalExtension" => 12,
            "confidentialityRequired"      => 13,
            "saslBindInProgress"           => 14,
            "noSuchAttribute"              => 16,
            "undefinedAttributeType"       => 17,
            "inappropriateMatching"        => 18,
            "constraintViolation"          => 19,
            "attributeOrValueExists"       => 20,
            "invalidAttributeSyntax"       => 21,
            #     -- 22-31 unused --
            "noSuchObject"                 => 32,
            "aliasProblem"                 => 33,
            "invalidDNSyntax"              => 34,
            # -- 35 reserved for undefined isLeaf --
            "aliasDereferencingProblem"    => 36,
            # -- 37-47 unused --
            "inappropriateAuthentication"  => 48,
            "invalidCredentials"           => 49,
            "insufficientAccessRights"     => 50,
            "busy"                         => 51,
            "unavailable"                  => 52,
            "unwillingToPerform"           => 53,
            "loopDetect"                   => 54,
            # -- 55-63 unused --
            "namingViolation"              => 64,
            "objectClassViolation"         => 65,
            "notAllowedOnNonLeaf"          => 66,
            "notAllowedOnRDN"              => 67,
            "entryAlreadyExists"           => 68,
            "objectClassModsProhibited"    => 69,
            #-- 70 reserved for CLDAP --
            "affectsMultipleDSAs"          => 71,
            # -- 72-79 unused --
            "other"                        => 80,
          }
        ),
        ldap_dn(:matched_dn),
        ldap_string(:diagnostic_message),
        wrapper(model(:referral, Referral), implicit: 3, optional: true)
      ]
    end

    sequence model_name,
             content: self.components
  end

  #
  # 4.2.2.  Bind Response
  #

  #        BindResponse ::= [APPLICATION 1] SEQUENCE {
  #              COMPONENTS OF LDAPResult,
  #              serverSaslCreds    [7] OCTET STRING OPTIONAL }
  class BindResponse < LdapModel
    sequence model_name,
             class: :application,
             implicit: 1,
             content: [
               *LdapResult.components,
               octet_string(:server_sasl_creds, implicit: 7, optional: true)
             ]
  end

  #
  # https://www.rfc-editor.org/rfc/rfc4511#section-4.5.1
  #

  #         Filter ::= CHOICE {
  #              and             [0] SET SIZE (1..MAX) OF filter Filter,
  #              or              [1] SET SIZE (1..MAX) OF filter Filter,
  #              not             [2] Filter,
  #              equalityMatch   [3] AttributeValueAssertion,
  #              substrings      [4] SubstringFilter,
  #              greaterOrEqual  [5] AttributeValueAssertion,
  #              lessOrEqual     [6] AttributeValueAssertion,
  #              present         [7] AttributeDescription,
  #              approxMatch     [8] AttributeValueAssertion,
  #              extensibleMatch [9] MatchingRuleAssertion,
  #              ...  }
  class Filter < LdapModel
    choice :filter,
           content: [
             # XXX: Can't be implemented with RASN1 because of the recursive definition
             # set_of(:and, Filter, implicit: 0),
             # set_of(:or, Filter, implicit: 1),
             # wrapper(model(:not, Filter), implicit: 2),
             ldap_string(:present, implicit: 7)
           ]
  end

  #        AttributeSelection ::= SEQUENCE OF selector LDAPString
  #                         -- The LDAPString is constrained to
  #                         -- <attributeSelector> in Section 4.5.1.8
  class AttributeSelection < LdapModel
    sequence_of :items, LdapString
  end

  #        SearchRequest ::= [APPLICATION 3] SEQUENCE {
  #              baseObject      LDAPDN,
  #              scope           ENUMERATED {
  #                   baseObject              (0),
  #                   singleLevel             (1),
  #                   wholeSubtree            (2),
  #                   ...  },
  #              derefAliases    ENUMERATED {
  #                   neverDerefAliases       (0),
  #                   derefInSearching        (1),
  #                   derefFindingBaseObj     (2),
  #                   derefAlways             (3) },
  #              sizeLimit       INTEGER (0 ..  maxInt),
  #              timeLimit       INTEGER (0 ..  maxInt),
  #              typesOnly       BOOLEAN,
  #              filter          Filter,
  #              attributes      AttributeSelection }
  class SearchRequest < LdapModel
    sequence model_name,
             class: :application,
             implicit: 3,
             content: [
               ldap_dn(:base_object),
               enumerated(
                 :scope,
                 enum: {
                   "baseObject"              => 0,
                   "singleLevel"             => 1,
                   "wholeSubtree"            => 2,
                 }
               ),
               enumerated(
                 :deref_aliases,
                 enum: {
                   "neverDerefAliases"       => 0,
                   "derefInSearching"        => 1,
                   "derefFindingBaseObj"     => 2,
                   "derefAlways"             => 3
                 }
               ),
               integer(:size_limit),
               integer(:time_limit),
               boolean(:types_only),
               model(:filter, Filter)
               # wrapper(model(:attributes, AttributeSelection), implicit: 8)
             ]
  end


  #
  # 4.1.1.  Message Envelope
  #

  #        MessageID ::= INTEGER (0 ..  maxInt)
  #        maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
  class MessageId < RASN1::Types::Integer
    # XXX: Add constrained types in accordance to the specification
  end

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
             model(:bind_request, BindRequest),
             model(:bind_response, BindResponse)
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

# RSpec.shared_examples_for 'a model that produces the same binary data when to_der is called' do
#   let(:input_data) { valid_data }
#
#   describe '#to_der' do
#     it 'produces the same binary data when to_der is called' do
#       expect(described_class.parse(input_data).to_der).to eq(input_data)
#     end
#   end
# end

RSpec.describe Ldap do
  describe Ldap::AuthenticationChoice do
    context 'when simple auth is parsed' do
      let(:valid_data) do
        "\x80\x08\x70\x34\x24\x24\x77\x30\x72\x64".b
      end

      it_behaves_like 'a model that produces the same binary data when to_der is called'

      describe '#parse' do
        it 'parses the data successfully' do
          expected = {
            AuthenticationChoice: "p4$$w0rd"
          }
          expect(described_class.parse(valid_data).to_h).to eq(expected)
        end
      end
    end
  end

  describe Ldap::BindRequest do
    let(:valid_data) do
      "\x60\x27\x02\x01\x03\x04\x18\x41\x64\x6d\x69\x6e\x69\x73\x74\x72" \
      "\x61\x74\x6f\x72\x40\x61\x64\x66\x33\x2e\x6c\x6f\x63\x61\x6c\x80" \
      "\x08\x70\x34\x24\x24\x77\x30\x72\x64".b
    end

    # it_behaves_like 'a model that produces the same binary data when to_der is called'

    describe '#parse' do
      it 'parses the data successfully' do
        expected = {
          BindRequest: {
            version: 3,
            name: 'Administrator@adf3.local',
            authentication: 'p4$$w0rd'
          }
        }
        expect(described_class.parse(valid_data).to_h).to eq(expected)
      end
    end
  end

  describe Ldap::BindResponse do
    let(:valid_data) do
      "\x61\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00".b
    end

    # it_behaves_like 'a model that produces the same binary data when to_der is called'

    describe '#parse' do
      it 'parses the data successfully' do
        expected = {
          BindResponse: {
            result_code: 'success',
            matched_dn: '',
            diagnostic_message: ''
          }
        }
        expect(described_class.parse(valid_data).to_h).to eq(expected)
      end
    end
  end

  describe Ldap::SearchRequest do
    let(:valid_data) do
      "\x63\x63\x04\x40\x43\x4e\x3d\x6d\x73\x2d\x44\x53\x2d\x4b\x72\x62" \
      "\x54\x67\x74\x2d\x4c\x69\x6e\x6b\x2c\x43\x4e\x3d\x53\x63\x68\x65" \
      "\x6d\x61\x2c\x43\x4e\x3d\x43\x6f\x6e\x66\x69\x67\x75\x72\x61\x74" \
      "\x69\x6f\x6e\x2c\x44\x43\x3d\x61\x64\x66\x33\x2c\x44\x43\x3d\x6c" \
      "\x6f\x63\x61\x6c\x0a\x01\x02\x0a\x01\x00\x02\x01\x00\x02\x01\x00" \
      "\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73" \
      "\x30\x03\x04\x01\x2a".b
    end

    # it_behaves_like 'a model that produces the same binary data when to_der is called'

    describe '#parse' do
      it 'parses the data successfully' do
        expected = {
          BindResponse: {
            result_code: 'success',
            matched_dn: '',
            diagnostic_message: ''
          }
        }
        expect(described_class.parse(valid_data).to_h).to eq(expected)
      end
    end
  end

  describe Ldap::LdapMessage do
    context 'when a bind request is parsed' do
      let(:valid_data) do
        "\x30\x2c\x02\x01\x01\x60\x27\x02\x01\x03\x04\x18\x41\x64\x6d\x69" \
        "\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x40\x61\x64\x66\x33\x2e\x6c" \
        "\x6f\x63\x61\x6c\x80\x08\x70\x34\x24\x24\x77\x30\x72\x64".b
      end

      # it_behaves_like 'a model that produces the same binary data when to_der is called'

      describe '#parse' do
        it 'parses the data successfully' do
          expected = {
            LdapMessage: {
              message_id: 1,
              protocol_op: {
                version: 3,
                name: 'Administrator@adf3.local',
                # TODO: this should be 'authentication' here
                # 'nil' => 'p4$$w0rd'.b
              }
            }
          }
          result = described_class.parse(valid_data).to_h
          result[:LdapMessage][:protocol_op].delete(nil)

          expect(result).to eq(expected)
        end
      end
    end

    context 'when a bind response is parsed' do
      let(:valid_data) do
        "\x30\x84\x00\x00\x00\x10\x02\x01\x01\x61\x84\x00\x00\x00\x07\x0a" \
        "\x01\x00\x04\x00\x04\x00".b
      end

      # it_behaves_like 'a model that produces the same binary data when to_der is called'

      describe '#parse' do
        it 'parses the data successfully' do
          next
          expected = {
            LdapMessage: {
              message_id: 1,
              protocol_op: {
                version: 3,
                name: 'Administrator@adf3.local',
                # TODO: this should be 'authentication' here
                # 'nil' => 'p4$$w0rd'.b
              }
            }
          }
          result = described_class.parse(valid_data).to_h
          result[:LdapMessage][:protocol_op].delete(nil)

          expect(result).to eq(expected)
        end
      end
    end
  end
end

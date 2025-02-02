# frozen_string_literal: true

module RASN1
  # This modules is a namesapce for all ASN.1 type classes.
  # @author Sylvain Daubert
  module Types
    # Give all primitive types
    # @return [Array<Types::Primitive>]
    def self.primitives
      @primitives ||= self.constants.map { |c| Types.const_get(c) }
                          .select { |klass| klass < Primitive }
    end

    # Give all constructed types
    # @return [Array<Types::Constructed>]
    def self.constructed
      @constructed ||= self.constants.map { |c| Types.const_get(c) }
                           .select { |klass| klass < Constructed }
    end

    # @private
    # Decode a DER string to extract identifier octets.
    # @param [String] der
    # @return [Array] Return ASN.1 class as Symbol, contructed/primitive as Symbol,
    #                 ID and size of identifier octets
    def self.decode_identifier_octets(der)
      first_octet = der.unpack1('C').to_i
      asn1_class = Types::Base::CLASSES.key(first_octet & Types::Base::CLASS_MASK)
      pc = (first_octet & Types::Constructed::ASN1_PC).positive? ? :constructed : :primitive
      id = first_octet & Types::Base::MULTI_OCTETS_ID

      size = if id == Types::Base::MULTI_OCTETS_ID
               id = 0
               der.bytes.each_with_index do |octet, i|
                 next if i.zero?

                 id = (id << 7) | (octet & 0x7f)
                 break i + 1 if (octet & 0x80).zero?
               end
             else
               1
             end

      [asn1_class, pc, id, size]
    end

    # Give ASN.1 type from a DER string. If ID is unknown, return a {Types::Base}
    # object.
    # @param [String] der
    # @return [Types::Base]
    # @raise [ASN1Error] +tag+ is out of range
    def self.id2type(der)
      # Define a cache for well-known ASN.1 types
      self.generate_id2type_cache unless defined? @id2types

      asn1class, pc, id, = self.decode_identifier_octets(der)
      # cache_id: check versus class and 5 LSB bits
      cache_id = der.unpack1('C') & 0xdf
      klass = cache_id < Types::Base::MULTI_OCTETS_ID ? @id2types[id] : Types::Base
      is_constructed = (pc == :constructed)
      options = { class: asn1class, constructed: is_constructed }
      options[:tag_value] = id if klass == Types::Base
      klass.new(options)
    end

    # @private Generate cache for {.id2type}
    def self.generate_id2type_cache
      constructed = self.constructed - [Types::SequenceOf, Types::SetOf]
      primitives = self.primitives - [Types::Enumerated]
      ary = (primitives + constructed).select { |type| type.const_defined? :ID }
                                      .map { |type| [type::ID, type] }
      @id2types = ary.to_h
      @id2types.default = Types::Base
      @id2types.freeze
    end

    # Define a new ASN.1 type from a base one.
    # This new type may have a constraint defines on it.
    # @param [Symbol,String] name New type name. Must start with a capital letter.
    # @param [Types::Base] from
    # @return [Class] newly created class
    def self.define_type(name, from:, &block)
      constraint = block.nil? ? nil : block.to_proc

      new_klass = Class.new(from) do
        include Constrained
      end
      new_klass.constraint = constraint

      self.const_set(name, new_klass)
      Model.define_type_accel(name.downcase, new_klass)

      # Empty type caches
      @primitives = nil
      @constructed = nil

      new_klass
    end
  end
end

require_relative 'types/base'
require_relative 'types/primitive'
require_relative 'types/boolean'
require_relative 'types/integer'
require_relative 'types/bit_string'
require_relative 'types/octet_string'
require_relative 'types/null'
require_relative 'types/object_id'
require_relative 'types/enumerated'
require_relative 'types/utf8_string'
require_relative 'types/numeric_string'
require_relative 'types/printable_string'
require_relative 'types/ia5string'
require_relative 'types/visible_string'
require_relative 'types/constructed'
require_relative 'types/sequence'
require_relative 'types/sequence_of'
require_relative 'types/set'
require_relative 'types/set_of'
require_relative 'types/choice'
require_relative 'types/any'
require_relative 'types/utc_time'
require_relative 'types/generalized_time'

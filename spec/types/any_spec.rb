# coding: utf-8
require_relative '../spec_helper'

class AnyModel < RASN1::Model
  sequence :seq,
           content: [any(:data), objectid(:id)]
end

class AnyModelOptional < RASN1::Model
  sequence :seq,
           content: [any(:data, optional: true), objectid(:id)]
end

module RASN1::Types


  describe Any do

    let(:os_der) { binary("\x30\x0a\x04\x03abc\x06\x03\x2a\x03\x04") }
    let(:int_der) { binary("\x30\x09\x02\x02\x00\x80\x06\x03\x2a\x03\x05") }
    let(:null_der) { binary("\x30\x07\x05\x00\x06\x03\x2a\x03\x06") }
    let(:void_der) { binary("\x30\x05\x06\x03\x2a\x03\x07") }

    describe '.type' do
      it 'gets ASN.1 type' do
        expect(Any.type).to eq('ANY')
      end
    end

    describe '#to_der' do
      let(:anymodel) { AnyModel.new }

      it 'generates a DER string with an octet string' do
        anymodel[:id].value = '1.2.3.4'
        anymodel[:data].value = OctetString.new(value: 'abc')
        expect(anymodel.to_der).to eq(os_der)
      end

      it 'generates a DER string with an integer' do
        anymodel[:id].value = '1.2.3.5'
        anymodel[:data].value = Integer.new(value: 128)
        expect(anymodel.to_der).to eq(int_der)
      end

      it 'generates a DER string with a Null object' do
        anymodel[:id].value = '1.2.3.6'
        expect(anymodel.to_der).to eq(null_der)
      end

      it 'generates a void string with nil value when optional' do
        anymodelopt = AnyModelOptional.new
        anymodelopt[:id].value = '1.2.3.7'
        expect(anymodelopt.to_der).to eq(void_der)
      end
    end

    describe '#parse!' do
      it 'parses any sequence with 2 elements and the first one is an OCTET STRING' do
        anymodel = AnyModel.parse(os_der)
        expect(anymodel[:data].value).to eq(binary("\x04\x03abc"))
        expect(anymodel[:id].value).to eq('1.2.3.4')
      end

      it 'parses any sequence with 2 elements and the first one is an INTEGER' do
        anymodel = AnyModel.parse(int_der)
        expect(anymodel[:data].value).to eq(binary("\x02\x02\x00\x80"))
        expect(anymodel[:id].value).to eq('1.2.3.5')
      end

      it 'raises on empty string' do
        expect { Any.new.parse!('') }.to raise_error(RASN1::ASN1Error)
      end

      it 'returns 0 on empty string when optional' do
        any = Any.new(optional: true)
        expect { any.parse!('') }.to_not raise_error
      end
    end

    describe '#inspect' do
      let(:any) { Any.new }

      it 'gets a String with NULL when value is nil' do
        expect(any.inspect).to eq('(ANY) NULL')
      end

      it 'gets a String with real type' do
        any.value = OctetString.new(value: '1234')
        expect(any.inspect).to eq('(ANY) OCTET STRING: "1234"')
        any.value = BitString.new(value: '1235', bit_length: 30)
        expect(any.inspect).to eq('(ANY) BIT STRING: "1235"')
        any.value = Integer.new(value: 45)
        expect(any.inspect).to eq('(ANY) INTEGER: 45')
      end

      it 'gets a String with an unknown type' do
        any.value = OctetString.new(value: '1234').to_der
        expect(any.inspect).to eq("(ANY) #{any.value.inspect}")
      end
    end
  end
end

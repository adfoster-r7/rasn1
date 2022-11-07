RSpec.shared_examples_for 'a model that produces the same binary data when to_der is called' do |*args|
    let(:input_data) { valid_data }

    describe '#to_der' do
      it 'produces the same binary data when to_der is called' do
        if args && args[0] == :pending
          is_equal = begin
            described_class.parse(input_data).to_der == input_data
          rescue => e
            false
          end
          if is_equal
            raise "incorrect pending for #{described_class}"
          end

          $stderr.puts "skipping: #{described_class}"
          next
        end

        expect(described_class.parse(input_data).to_der).to eq(input_data)
      end
    end
  end

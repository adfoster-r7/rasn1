require 'rasn1'

class Filter < RASN1::Model
  choice :filter,
         content: [
           wrapper(model(:not, Filter), implicit: 2),
           # ... rest ommitted for simplicity...
           octet_string(:present, implicit: 7)
         ]
end

input = "\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73".b
pp Filter.parse(input)

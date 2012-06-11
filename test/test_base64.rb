$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'test/unit'
require 'rack/facebook/signed_request'

class TestBase64 < Test::Unit::TestCase

    def test_base64_ignores_broken_padding
        sr = Rack::Facebook::SignedRequest.new(nil, nil)
        # U's ascii bits are 01010101
        assert_equal("U" * 4, sr.send(:base64_url_decode, "VVVVVQ=="))
        assert_equal("U" * 4, sr.send(:base64_url_decode, "VVVVVQ"))
    end

end

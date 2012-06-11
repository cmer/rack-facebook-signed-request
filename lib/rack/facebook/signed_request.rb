require 'openssl'
require 'base64'
require 'yajl'

#
# Gemified and borrowed heavily from Ole Riesenberg:
# http://oleriesenberg.com/2010/07/22/facebook-graph-api-with-fbml-canvas-apps.html
#
module Rack
  module Facebook
    class SignedRequest
      def initialize(app, options, &condition)
        @app = app
        @condition = condition
        @options = options
      end

      def call(env)
        @request = Rack::Request.new(env)
        # RESTify the default POST request from Facebook
        if request.POST['signed_request']
          env['REQUEST_METHOD'] = 'GET'
          env['facebook.signed_request'] = request.POST['signed_request'] if request.POST['signed_request']

          app_id, secret = [@options.fetch(:app_id), @options.fetch(:secret)]
          facebook_params = resolve_from_signed_request!(secret) || resolve_from_cookie!(app_id, secret)
          request.params['facebook_params'] = facebook_params if facebook_params
          env['facebook.params'] = facebook_params if facebook_params
        end

        unless @options[:inject_facebook]
          @app.call(env)
        else
          inject_facebook_script(env)
        end
      end

      private

        attr_reader :request

        def resolve_from_cookie!(app_id, secret)
          # extract contents
          cookie = request.cookies["fbs_#{app_id}"]
          return nil unless cookie

          hash = {}
          data = cookie.gsub(/"/,"")
          data.split('&').each do |str|
            parts = str.split('=')
            hash[parts.first] = parts.last
          end
          unless signed_cookie_is_valid?(secret, hash)
            return Rack::Response.new(["Invalid cookie signature"], 400).finish
          end

          # map cookie params to signed request equivalents
          {
            'oauth_token' => hash.fetch('access_token'),
            'expires' => hash.fetch('expires'),
            'user_id' => hash.fetch('uid')
          }
        end

        def resolve_from_signed_request!(secret)
          return nil unless request.params['signed_request']
          signed_request = request.params['signed_request']
          signature, signed_params = signed_request.split('.')
          unless signed_request_is_valid?(secret, signature, signed_params)
            return Rack::Response.new(["Invalid signed request"], 400).finish
          end
          Yajl::Parser.new.parse(base64_url_decode(signed_params))
        end

        def signed_request_is_valid?(secret, signature, params)
          signature = base64_url_decode(signature)
          expected_signature = OpenSSL::HMAC.digest('SHA256', secret, params.tr("-_", "+/"))
          return signature == expected_signature
        end

        def signed_cookie_is_valid?(secret, hash)
          sorted_keys = hash.keys.reject {|k| k== 'sig'}.sort
          test_string = ""
          sorted_keys.each do |key|
            test_string += "#{key}=#{hash[key]}"
          end
          test_string += secret
          Digest::MD5.hexdigest(test_string) == hash['sig']
        end

        def base64_url_decode(str)
          str += '=' * (4 * (str.length / 4.0).ceil - str.length)
          Base64.decode64(str.tr("-_", "+/"))
        end

        # borrowed from Michael Bleigh's Rack Facebook_Connect for rewriting of the response body
        def inject_facebook_script(env) #:nodoc:
          status, headers, responses = @app.call(env)
          responses = Array(responses) unless responses.respond_to?(:each)

          if headers["Content-Type"] =~ %r{(text/html)|(application/xhtml+xml)}
            resp = []
            responses.each do |r|
              r.sub! /(<html[^\/>]*)>/i, '\1 xmlns:fb="http://www.facebook.com/2008/fbml">'
              r.sub! /<\/body>/i, <<-HTML
                <div id="fb-root"></div>
                <script>
                  window.fbAsyncInit = function() {
                    FB.init({
                      appId  : '#{@options.fetch(:app_id)}',
                      status : #{@options[:status] || true}, // check login status
                      cookie : #{@options[:cookie] || true}, // enable cookies to allow the server to access the session
                      #{"channelUrl : '#{@options[:channel_url]}', // add channelURL to avoid IE redirect problems" if @options[:channel_url]}
                      xfbml  : #{@options[:xfbml] || true}  // parse XFBML
                    });
                  };

                  (function() {
                    var e = document.createElement('script'); e.async = true;
                    e.src = document.location.protocol + '//connect.facebook.net/#{@options[:lang] || 'en_US'}/all.js';
                    document.getElementById('fb-root').appendChild(e);
                  }());
                </script>
                </body>
              HTML
              resp << r
            end
          end
          Rack::Response.new(resp || responses, status, headers).finish
        end
    end
  end
end

require 'openssl'

module Rafaday

  class BodySigningMiddleware

    def initialize(app, options={})
      @app = app
      @secret = options.fetch(:secret) { '' }
      @digest = options.fetch(:digest) { 'sha1' }
    end

    def call(env)
      if env[:body]
        digest = OpenSSL::HMAC.new @secret, @digest
        digest << env[:body].to_s
        url = env[:url]
        query = url.query_values || {}
        url.query_values = query.merge :sig => digest.to_s
      end
      @app.call env
    end
  end

end

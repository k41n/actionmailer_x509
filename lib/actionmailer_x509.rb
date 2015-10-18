require 'actionmailer_x509/railtie' if defined?(Rails)
require "openssl"

module ActionMailer #:nodoc:
  class Base #:nodoc:

    def self.adv_attr_accessor(name, deprecation=nil)
      ivar = "@#{name}"
      deprecation ||= "Please pass :#{name} as hash key to mail() instead"
      class_eval <<-ACCESSORS, __FILE__, __LINE__ + 1
        def #{name}=(value)
          ActiveSupport::Deprecation.warn "#{name}= is deprecated. #{deprecation}"
          #{ivar} = value
        end
        def #{name}(*args)
          raise ArgumentError, "expected 0 or 1 parameters" unless args.length <= 1
          if args.empty?
            ActiveSupport::Deprecation.warn "#{name}() is deprecated and will be removed in future versions."
            #{ivar} if instance_variable_names.include?(#{ivar.inspect})
          else
            ActiveSupport::Deprecation.warn "#{name}(value) is deprecated. #{deprecation}"
            #{ivar} = args.first
          end
        end
      ACCESSORS
      self.protected_instance_variables << ivar if self.respond_to?(:protected_instance_variables)
    end

    @@default_x509_sign = false
    @@default_x509_sign_cert = nil
    @@default_x509_sign_key = nil
    @@default_x509_sign_passphrase = nil

    @@default_x509_crypt = false
    @@default_x509_crypt_cert = nil
    @@default_x509_crypt_cipher = "des"

    @@default_x509_sign_and_crypt_method = :smime

    # Should we sign the outgoing mail?
    adv_attr_accessor :x509_sign

    # Should we crypt the outgoing mail?
    adv_attr_accessor :x509_crypt

    # Which certificate will be used for signing.
    adv_attr_accessor :x509_sign_cert

    # Which private key will be used for signing.
    adv_attr_accessor :x509_sign_key

    # Which certificate will be used for crypting.
    adv_attr_accessor :x509_crypt_cert

    # Which encryption algorithm will be used for crypting.
    adv_attr_accessor :x509_crypt_cipher

    # Which signing method is used. NOTE: For later, if needed.
    adv_attr_accessor :x509_sign_and_crypt_method

    # Passphrase for the sign key, if needed.
    adv_attr_accessor :x509_sign_passphrase

    # We replace the initialize methods and run a new method if signing or crypting is required
    def initialize_with_sign_and_crypt(method_name, *parameters)
      mail = initialize_without_sign_and_crypt(method_name, *parameters)

      x509_initvar()

      # If we need to sign the outgoing mail.
      if should_sign? or should_crypt?
        if logger
          logger.debug("actionmailer_x509: We should sign and\or crypt the mail with #{@x509_sign_and_crypt_method} method.")
        end
        __send__("x509_#{@x509_sign_and_crypt_method}", mail)
      end

    end
    alias_method_chain :initialize, :sign_and_crypt

    def smart_read(filename_or_cert)
      if /^\A\s*-----.*-----\s*?\z/m =~ filename_or_cert
        filename_or_cert
      else
        File::read(filename_or_cert)
      end
    end

    # X509 SMIME signing and\or crypting
    def x509_smime(mail)
      if logger
        logger.debug("actionmailer_x509: X509 SMIME signing with cert #{@x509_cert} and key #{@x509_key}") if should_sign?
        logger.debug("actionmailer_x509: X509 SMIME crypt with cert #{@x509_cert}") if should_crypt?
      end

      # We should set content_id, otherwise Mail will set content_id after signing and will broke sign
      mail.content_id ||= nil
      mail.parts.each {|p| p.content_id ||= nil}

      # We can remove the headers from the older mail we encapsulate.
      # Leaving allows to have the headers signed too within the encapsulated
      # email, but MUAs make no use of them... :(
      #
      # mail.subject = nil
      # mail.to = nil
      # mail.cc = nil
      # mail.from = nil
      # mail.date = nil
      # headers.each { |k, v| mail[k] = nil }
      # mail['Content-Type'] = 'text/plain'
      # mail.mime_version = nil

      # We load certificate and private key
      if should_sign?
        sign_cert = OpenSSL::X509::Certificate.new( smart_read(@x509_sign_cert) )
        sign_prv_key = OpenSSL::PKey::RSA.new( smart_read(@x509_sign_key), @x509_sign_passphrase)
      end

      if should_crypt?
        crypt_cert = OpenSSL::X509::Certificate.new( smart_read(@x509_crypt_cert) )
        cipher = OpenSSL::Cipher.new(@x509_crypt_cipher)
      end

#      begin
        # Sign and crypt the mail

        # NOTE: the one following line is the slowest part of this code, signing is sloooow
        p7 = mail.encoded
        p7 = OpenSSL::PKCS7.sign(sign_cert,sign_prv_key, p7, [], OpenSSL::PKCS7::DETACHED) if should_sign?
        p7 = OpenSSL::PKCS7.encrypt([crypt_cert], (should_sign? ? OpenSSL::PKCS7::write_smime(p7) : p7), cipher, nil) if should_crypt?
        smime0 = OpenSSL::PKCS7::write_smime(p7)

        # Adding the signature part to the older mail
        newm = Mail.new(smime0)

        # We need to overwrite the content-type of the mail so MUA notices this is a signed mail
#        newm.content_type = 'multipart/signed; protocol="application/x-pkcs7-signature"; micalg=sha1; '
         newm.delivery_method(mail.delivery_method.class, mail.delivery_method.settings)
         newm.subject = mail.subject
         newm.to = mail.to
         newm.cc = mail.cc
         newm.from = mail.from
         newm.mime_version = mail.mime_version
         newm.date = mail.date
#        newm.body = "This is an S/MIME signed message\n"
#        headers.each { |k, v| m[k] = v } # that does nothing in general

        # NOTE: We can not use this as we need a B64 encoded signature, and no
        # methods provides it within the Ruby OpenSSL library... :(
        #
        # We add the signature
        # signature = Mail.new
        # signature.mime_version = '1.0'
        # signature['Content-Type'] = 'application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"'
        # signature['Content-Transfer-Encoding'] = 'base64'
        # signature['Content-Disposition']  = 'attachment; filename="smime.p7m"'
        # signature.body = p7sign.to_s
        # newm.parts << signature

        @_message = newm
#      rescue Exception => detail
#        logger.error("Error while SMIME signing and\or crypting the mail : #{detail}")
#      end

      ## logger.debug("x509_sign_smime, resulted email\n-------------( test X509 )----------\n#{m.encoded}\n-------------( test X509 )----------")

    end

    protected

    # Shall we sign the mail?
    def should_sign?
      @should_sign ||= __should_sign?
    end

    def __should_sign?
      if @x509_sign == true
        if not @x509_sign_cert.nil? and not @x509_sign_key.nil?
          return true
        else
          logger.info "X509 signing required, but no certificate and key files configured"
        end
      end
      return false
    end

    # Shall we crypt the mail?
    def should_crypt?
      @should_crypt ||= __should_crypt?
    end

    def __should_crypt?
      if @x509_crypt == true
        if not @x509_crypt_cert.nil?
          return true
        else
          logger.info "X509 crypting required, but no certificate file configured"
        end
      end
      return false
    end

    # Initiate from the default class attributes
    def x509_initvar
      @x509_sign_and_crypt_method ||= @@default_x509_sign_and_crypt_method
      @x509_sign                  ||= @@default_x509_sign
      @x509_crypt                 ||= @@default_x509_crypt
      @x509_crypt_cert            ||= @@default_x509_crypt_cert
      @x509_crypt_cipher          ||= @@default_x509_crypt_cipher
      @x509_sign_cert             ||= @@default_x509_sign_cert
      @x509_key                   ||= @@default_x509_sign_key
      @x509_sign_passphrase       ||= @@default_x509_sign_passphrase
    end
  end
end

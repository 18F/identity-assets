# rubocop:disable Metrics/ModuleLength
module ServiceProviderConfigValidator
  require 'yaml'
  require 'openssl'
  require 'byebug'

  # rubocop:disable Metrics/MethodLength
  def collect_sp_errors(issuer, config)
    @issuer = issuer
    @config = config
    @sp_errors = []

    require_agency
    require_agency_id
    require_friendly_name
    require_valid_issuer
    require_valid_logo_config
    require_valid_ial_config
    require_valid_restrict_to_deploy_env
    validate_return_to_sp_url
    validate_push_notification_url
    validate_cert_config
    validate_protocol_config
    validate_help_text

    @sp_errors
  end
  # rubocop:enable Metrics/MethodLength

  private

  def require_agency
    return if @config['agency'].present?

    @sp_errors << 'agency must be defined'
  end

  def require_agency_id
    return if @config['agency_id'].present?

    @sp_errors << 'agency_id must be defined'
  end

  def require_friendly_name
    return if @config['friendly_name'].present?

    @sp_errors << 'friendly_name must be defined'
  end

  def require_valid_issuer
    if @issuer.present?
      @sp_errors << 'issuer must be valid' if @issuer =~ /,|\s|'|"/
    else
      @sp_errors << 'issuer must be defined'
    end
  end

  def require_valid_logo_config
    if @config['logo'].present?
      validate_logo_file_presence
    else
      @sp_errors << 'Service provider logo must be defined'
    end
  end

  def validate_logo_file_presence
    return unless @config['logo'].present?

    logo_file_name = ['assets/images/logos', @config['logo']].join('/')
    return if File.exist?(logo_file_name)

    @sp_errors << "No file exists for #{logo_file_name}"
  end

  # rubocop:disable Metrics/MethodLength
  def require_valid_ial_config
    if @config['ial'].present?
      unless @config['ial'] == 1 || @config['ial'] == 2
        @sp_hash['valid'] = false
        @sp_errors << 'ial must be defined as either 1 or 2'
        return
      end
      if @config['ial'] == 2
        require_valid_attribute_bundle
        require_valid_ftp_url
      end
    else
      @sp_errors << 'ial must be defined'
    end
  end
  # rubocop:enable Metrics/MethodLength

  def require_valid_attribute_bundle
    if @config['attribute_bundle'].present?
      validate_attribute_bundle
    else
      @sp_errors << 'attribute_bundle must be defined'
    end
  end

  def validate_attribute_bundle
    allowed_attributes = %w[email first_name middle_name
                            last_name dob ssn address1 address2
                            city state zipcode phone]
    return if (@config['attribute_bundle'] - allowed_attributes).empty?

    @sp_errors << 'attribute_bundle must be valid - may only include: '\
                  'email, first_name, middle_name, last_name, dob, '\
                  'ssn, address1, address2, city, state, zipcode, phone'
  end

  def require_valid_ftp_url
    if @config['failure_to_proof_url'].present?
      parsed_uri = URI.parse(@config['failure_to_proof_url'])
      return if parsed_uri.scheme.present? && parsed_uri.host.present?

      @sp_errors << 'failure to proof url must be valid'
    else
      @sp_errors << 'failure to proof url must be defined'
    end
  end

  def require_valid_restrict_to_deploy_env
    if @config['restrict_to_deploy_env'].present?
      return if @config['restrict_to_deploy_env'] == 'prod' ||
                @config['restrict_to_deploy_env'] == 'staging'

      @sp_errors << 'restrict_to_deploy_env must be defined as either '\
                           "prod' or 'staging'"
    else
      @sp_errors << 'restrict_to_deploy_env must be defined'
    end
  end

  def validate_return_to_sp_url
    return unless @config['web']

    if @config['return_to_sp_url'].present?
      parsed_uri = URI.parse(@config['return_to_sp_url'])
      return if parsed_uri.scheme.present? && parsed_uri.host.present?

      @sp_errors << 'return_to_sp_url must be valid uri'
    else
      @sp_errors << 'return_to_sp_url must be defined for web '\
                           'application service provider'
    end
  end

  def validate_push_notification_url
    return unless @config['push_notification_url']

    parsed_uri = URI.parse(@config['push_notification_url'])
    return if parsed_uri.scheme.present? && parsed_uri.host.present?

    @sp_errors << 'push_notification_url must be valid uri'
  end

  def validate_cert_config
    return if @config['native'] || @config['oidc_pkce']

    if @config['cert'].present?
      cert_file_exists? && valid_cert_file?
    else
      @sp_errors << 'cert must be defined for web application service provider'
    end
  end

  def cert_file_name
    ['certs/sp', "#{@config['cert']}.crt"].join('/')
  end

  # rubocop:disable Metrics/AbcSize
  def valid_cert_file?
    return true if cert.not_after.to_i > 6.months.from_now.to_i &&
        cert.public_key.n.num_bits >= 2048

    if cert.public_key.n.num_bits < 2048
      @sp_errors << "#{cert_file_name} must be a cert at least 2048 bits "\
                    'in length'
    elsif cert.not_after.to_i <= 6.months.from_now.to_i
      @sp_errors << "#{cert_file_name} must be a cert that does not expire in "\
                    'the next six months'
    end
  end
  # rubocop:enable Metrics/AbcSize

  def cert
    OpenSSL::X509::Certificate.new(File.read(cert_file_name))
  end

  def cert_file_exists?
    return true if File.exist?(cert_file_name)

    @sp_errors << "No file exists for #{cert_file_name}"
  end

  def validate_protocol_config
    if @config['protocol'].present?
      if valid_protocol_value?
        validate_saml_properties if @config['protocol'] == 'saml'
        validate_oidc_properties if @config['protocol'] == 'oidc'
      end
    else
      @sp_errors << 'Service provider protocol must be defined'
    end
  end

  def valid_protocol_value?
    return true if @config['protocol'] == 'saml' ||
                   @config['protocol'] == 'oidc'

    @sp_errors << "protocol must be defined as 'saml' or 'oidc'"
    false
  end

  def validate_saml_properties
    require_acs_url && require_acs_logout_url
  end

  def validate_oidc_properties
    require_redirect_uris && validate_redirect_uris
  end

  def require_acs_url
    return true if @config['acs_url'].present?

    @sp_errors << 'acs_url must be defined for SAML service provider'
  end

  def require_acs_logout_url
    return true if @config['assertion_consumer_logout_service_url'].present?

    @sp_errors << 'assertion_consumer_logout_service_url must be '\
                         'defined for SAML service provider'
  end

  def require_redirect_uris
    return true if @config['redirect_uris'].present?

    @sp_errors << 'redirect_uris must be defined for OIDC '\
                         'service provider'
  end

  def validate_redirect_uris
    @config['redirect_uris'].each do |uri|
      parsed_uri = URI.parse(uri)
      next if parsed_uri.scheme.present? && parsed_uri.host.present?

      @sp_errors << 'redirect_uris must be valid for OIDC '\
                           'service provider'
      break
    end
  end

  def validate_help_text
    return unless @config['help_text'].present?

    if (@config['help_text'].keys - %w[forgot_password sign_up sign_in]).empty?
      @config['help_text'].each do |section|
        next if (section.last.keys - %w[en es fr]).empty?

        @sp_errors << 'help_text must be formatted properly'
      end
    else
      @sp_errors << 'help_text must be formatted properly'
    end
  end
end
# rubocop:enable Metrics/ModuleLength

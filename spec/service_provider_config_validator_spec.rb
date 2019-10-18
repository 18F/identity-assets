require 'spec_helper'

config_file = File.read('spec/fixtures/test_service_providers.yml')
config_yaml = YAML.load(config_file)
sp = config_yaml.first

describe ServiceProviderConfigValidator do
  let(:issuer) { sp.first }
  let(:config) do
    HashWithIndifferentAccess.new(sp.last)
  end

  after(:each) { config }

  context 'when the issuer is invalid' do
    let(:bad_issuer) { 'bad,,, issuer' }

    it 'collects an error about the invalid issuer' do
      expect(collect_sp_errors(bad_issuer, config)).to contain_exactly 'issuer must be valid'
      issuer
    end
  end

  context 'when the friendly_name is missing' do
    let(:bad_config) { config.update('friendly_name': '') }

    it 'collects an error about the friendly_name being undefined' do
      expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'friendly_name must be defined'
    end
  end

  context 'when the agency is missing' do
    let(:bad_config) { config.update('agency': '') }

    it 'collects an error about the agency being undefined' do
      expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'agency must be defined'
    end
  end

  context 'when the agency_id is missing' do
    let(:bad_config) { config.update('agency_id': '') }

    it 'collects an error about the agency_id being undefined' do
      expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'agency_id must be defined'
    end
  end

  context 'when the ial is missing' do
    let(:bad_config) { config.update('ial': '') }

    it 'collects an error about the ial being undefined' do
      expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'ial must be defined'
    end
  end

  context 'when the ial is defined incorrectly' do
    let(:bad_config) { config.update('ial': 3) }

    it 'collects an error about the ial being incorrectly defined' do
      expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'ial must be defined as either 1 or 2'
    end
  end

  context 'when the service provider is ial 2' do
    let(:ial2_config) { config.update('ial': 2, 'failure_to_proof_url': 'https://example.com', 'attribute_bundle': %w[email first_name]) }
    after(:each) { ial2_config }

    context 'when the failure_proof_url is missing' do
      let(:bad_config) { ial2_config.update('failure_to_proof_url': '') }

      it 'collects an error about the failure_to_proof_url being undefined' do
        expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'failure_to_proof_url must be defined'
      end
    end

    context 'when the failure_proof_url is an invalid url' do
      let(:bad_config) { ial2_config.update('failure_to_proof_url': 'invalidurl.com') }

      it 'collects an error about the failure_to_proof_url being an invalid uri' do
        expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'failure_to_proof_url must be valid uri'
      end
    end

    context 'when the attribute_bundle is missing' do
      let(:bad_config) { ial2_config.update('attribute_bundle': '') }

      it 'collects an error about the attribute_bundle being undefined' do
        expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'attribute_bundle must be defined'
      end
    end

    context 'when the attribute_bundle is invalid' do
      let(:bad_config) { ial2_config.update('attribute_bundle': ['invalid_attribute']) }

      it 'collects an error about the attribute_bundle being invalid' do
        expect(collect_sp_errors(issuer, bad_config)).
          to contain_exactly 'attribute_bundle must be valid - may only '\
                             'include: email, first_name, middle_name, '\
                             'last_name, dob, ssn, address1, address2, city, '\
                             'state, zipcode, phone'
      end
    end
  end

  context 'when the logo is missing' do
    let(:bad_config) { config.update('logo': '') }

    it 'collects an error about the logo being undefined' do
      expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'logo must be defined'
    end
  end

  context 'when the logo does not correspond to a file' do
    let(:bad_config) { config.update('logo': 'not_a_file.png') }
    let(:logo_path) { ['assets/images/logos', bad_config['logo']].join('/') }

    it 'collects an error about the logo not having a corresponding file' do
      expect(collect_sp_errors(issuer, bad_config)).to contain_exactly "No logo file exists for #{logo_path}"
    end
  end

  context 'when the service provider is a web application' do
    let(:web_config) { config.update('native': false, 'cert': 'example', 'return_to_sp_url': 'https://example.com') }
    after(:each) { web_config }

    context 'when the cert is not defined' do
      let(:bad_config) { web_config.update('cert': '') }

      it 'collects an error about the cert being undefined' do
        expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'cert must be defined for web application service provider'
      end
    end

    context 'when the cert does not correspond to a file' do
      let(:bad_config) { web_config.update('cert': 'not_a_file') }
      let(:cert_file_path) { ['certs/sp', "#{bad_config['cert']}.crt"].join('/') }

      it 'collects an error about the cert not having a corresponding file' do
        expect(collect_sp_errors(issuer, bad_config)).to contain_exactly "No cert file exists for #{cert_file_path}"
      end
    end

    context 'when the cert is to be out of date within six months' do
      let(:bad_config) { web_config.update('cert': 'expired_cert') }
      let(:cert_file_path) { ['certs/sp', "#{bad_config['cert']}.crt"].join('/') }

      it 'collects an error about the cert being out of date within six months' do
        expect(collect_sp_errors(issuer, bad_config)).to contain_exactly "#{cert_file_path} must be a cert that does not expire in the next six months"
      end
    end

    context 'when the cert is too short' do
      let(:bad_config) { web_config.update('cert': 'too_short_cert') }
      let(:cert_file_path) { ['certs/sp', "#{bad_config['cert']}.crt"].join('/') }

      it 'collects an error about the cert being too short' do
        expect(collect_sp_errors(issuer, bad_config)).to contain_exactly "#{cert_file_path} must be a cert at least 2048 bits in length"
      end
    end

    context 'when the return_to_sp_url is missing' do
      let(:bad_config) { web_config.update('return_to_sp_url': '') }

      it 'collects an error about the return_to_sp_url being undefined' do
        expect(collect_sp_errors(issuer, bad_config))
          .to contain_exactly 'return_to_sp_url must be defined for web '\
                              'application service provider'
      end
    end

    context 'when the return_to_sp_url is an invalid url' do
      let(:bad_config) { web_config.update('return_to_sp_url': 'invalidurl.com') }

      it 'collects an error about the return_to_sp_url being an invalid uri' do
        expect(collect_sp_errors(issuer, bad_config))
          .to contain_exactly 'return_to_sp_url must be valid uri'
      end
    end
  end

  context 'when the service provider is a native app' do
    let(:native_config) { config.update('native': true, 'cert': '') }
    after(:each) { native_config }

    context 'when the cert is not defined' do
      it 'does not collect an error about the cert being undefined' do
        expect(collect_sp_errors(issuer, native_config)).to be_empty
      end
    end

    context 'when a return_to_sp_url is set' do
      let(:bad_config) { native_config.update('return_to_sp_url': 'https://example.com') }

      it 'collects an error about the return_to_sp_url being disallowed' do
        expect(collect_sp_errors(issuer, bad_config))
          .to contain_exactly 'return_to_sp_url must not be set for a '\
                              'native application service provider'
      end
    end
  end

  context 'when there is an invalid push_notification_url' do
    let(:bad_config) { config.update('push_notification_url': 'invalidurl.com') }

    it 'collects an error about the push_notification_url being an invalid uri' do
      expect(collect_sp_errors(issuer, bad_config))
          .to contain_exactly 'push_notification_url must be valid uri'
    end
  end

  context 'when there is invalid help_text' do
    let(:bad_config) { config.update('help_text': { 'bad_key': 'bad' }) }

    it 'collects an error about the help_text being formatted incorrectly' do
      expect(collect_sp_errors(issuer, bad_config))
          .to contain_exactly 'help_text must be formatted properly'
    end
  end

  context 'when the protocol is missing' do
    let(:bad_config) { config.update('protocol': '') }

    it 'collects an error about the protocol being undefined' do
      expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'protocol must be defined'
    end
  end

  context 'when the protocol is saml' do
    let(:saml_config) do
      config.update('protocol': 'saml', 'acs_url': 'https://example.com',
                    'assertion_consumer_logout_service_url': 'https://example.com')
    end
    after(:each) { saml_config }

    context 'when the acs_url is missing' do
      let(:bad_config) { saml_config.update('acs_url': '') }

      it 'collects an error about the acs_url being undefined' do
        expect(collect_sp_errors(issuer, bad_config))
          .to contain_exactly 'acs_url must be defined for SAML service provider'
      end
    end

    context 'when there is an invalid acs_url' do
      let(:bad_config) { saml_config.update('acs_url': 'invalidurl.com') }

      it 'collects an error about the acs_url being an invalid uri' do
        expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'acs_url must be valid uri'
      end
    end

    context 'when the assertion_consumer_logout_service_url is missing' do
      let(:bad_config) { saml_config.update('assertion_consumer_logout_service_url': '') }

      it 'collects an error about the assertion_consumer_logout_service_url being undefined' do
        expect(collect_sp_errors(issuer, bad_config))
          .to contain_exactly 'assertion_consumer_logout_service_url must be '\
                              'defined for SAML service provider'
      end
    end

    context 'when there is an invalid assertion_consumer_logout_service_url' do
      let(:bad_config) { saml_config.update('assertion_consumer_logout_service_url': 'invalidurl.com') }

      it 'collects an error about the assertion_consumer_logout_service_url being an invalid uri' do
        expect(collect_sp_errors(issuer, bad_config))
          .to contain_exactly 'assertion_consumer_logout_service_url must be valid uri'
      end
    end
  end

  context 'when the protocol is oidc' do
    let(:oidc_config) do
      config.update('protocol': 'oidc', 'redirect_uris': ['https://example.com'] )
    end
    after(:each) { oidc_config }

    context 'when the redirect_uris are missing' do
      let(:bad_config) { oidc_config.update('redirect_uris': '') }

      it 'collects an error about the redirect_uris being undefined' do
        expect(collect_sp_errors(issuer, bad_config))
          .to contain_exactly 'redirect_uris must be defined for OIDC service provider'
      end
    end

    context 'when the redirect_uris are missing' do
      let(:bad_config) { oidc_config.update('redirect_uris': ['invalidurl.com']) }

      it 'collects an error about redirect_uris being invalid' do
        expect(collect_sp_errors(issuer, bad_config))
          .to contain_exactly 'redirect_uris must be valid for OIDC service provider'
      end
    end
  end

  context 'when the restrict_to_deploy_env is missing' do
    let(:bad_config) { config.update('restrict_to_deploy_env': '') }

    it 'collects an error about the restrict_to_deploy_env being undefined' do
      expect(collect_sp_errors(issuer, bad_config))
        .to contain_exactly 'restrict_to_deploy_env must be defined'
    end
  end

  context 'when the restrict_to_deploy_env is defined incorrectly' do
    let(:bad_config) { config.update('restrict_to_deploy_env': 'invalid_env') }

    it 'collects an error about the restrict_to_deploy_env being undefined' do
      expect(collect_sp_errors(issuer, bad_config))
        .to contain_exactly 'restrict_to_deploy_env must be defined as either '\
                            "'prod' or 'staging'"
    end
  end
end

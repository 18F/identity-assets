require 'active_support/core_ext'
require 'minitest/autorun'
require 'yaml'
require 'openssl'

config_file = File.read('config/test_service_providers.yml')
config_yaml = YAML.safe_load(config_file)

# rubocop:disable Metrics/BlockLength
describe 'Service Provider config' do
  it 'should be parsable yaml' do
    assert config_yaml.present?
  end

  config_yaml.each do |sp|
    issuer = sp.first
    config = sp.last

    describe issuer.to_s do
      it 'should have a valid issuer' do
        assert !issuer.match?(/,|\s|'|"/)
      end

      it 'should have a friendly_name value' do
        assert config['friendly_name'].present?
      end

      it 'should have an agency value' do
        assert config['agency'].present?
      end

      it 'should have an agency_id value' do
        assert config['agency_id'].present?
      end

      it 'should have a valid push_notification_url if there is one' do
        next unless config['push_notification_url']

        parsed_uri = URI.parse(config['push_notification_url'])
        assert parsed_uri.scheme.present? && parsed_uri.host.present?
      end

      it 'should have protocol value' do
        assert config['protocol'].present?
      end

      it 'should have protocol value' do
        assert config['protocol'] == 'saml' ||
               config['protocol'] == 'oidc'
      end

      describe 'return_to_sp_url' do
        it 'should have a value' do
          assert config['return_to_sp_url'].present?
        end

        it 'should be a valid url' do
          next unless config['return_to_sp_url'].present?

          parsed_uri = URI.parse(config['return_to_sp_url'])
          assert parsed_uri.scheme.present? && parsed_uri.host.present?
        end
      end

      describe 'restrict_to_deploy_env' do
        it 'should have a value' do
          assert config['restrict_to_deploy_env'].present?
        end

        it 'should only have prod or staging as values' do
          assert config['restrict_to_deploy_env'] == 'prod' ||
                 config['restrict_to_deploy_env'] == 'staging'
        end
      end

      describe 'logo' do
        it 'should have a value' do
          assert config['logo'].present?
        end

        it 'should have corresponding logo file' do
          next unless config['logo'].present?

          logo_file_name = ['assets/images/logos', config['logo']].join('/')
          assert File.exist?(logo_file_name)
        end
      end

      describe 'cert' do
        next if config['native'] || config['oidc_pkce']

        it 'should have a value' do
          assert config['cert'].present?
        end

        describe 'corresponding cert file' do
          next unless config['cert'].present?

          cert_file_name = ['certs/sp', "#{config['cert']}.crt"].join('/')

          it 'should exist' do
            assert File.exist?(cert_file_name)
          end

          describe 'cert validity' do
            next unless File.exist?(cert_file_name)

            cert = OpenSSL::X509::Certificate.new(File.read(cert_file_name))

            it 'should have acceptable expiry' do
              assert cert.not_after.to_i > 6.months.from_now.to_i
            end

            it 'should be at least 2048 bits in length' do
              assert cert.public_key.n.num_bits >= 2048
            end
          end
        end
      end

      describe 'ial' do
        it 'should have a value' do
          assert config['ial'].present?
        end

        it 'should have only 1 or 2 as values' do
          next unless config['ial'].present?

          assert config['ial'] == 1 || config['ial'] == 2
        end

        describe 'ial2' do
          next unless config['ial'] == 2

          it 'should have a failure_to_proof_url' do
            assert config['failure_to_proof_url'].present?
          end

          it 'should have a valid failure_to_proof_url' do
            next unless config['failure_to_proof_url'].present?

            parsed_uri = URI.parse(config['failure_to_proof_url'])
            assert parsed_uri.scheme.present? && parsed_uri.host.present?
          end

          describe 'attribute_bundle' do
            it 'should have a value' do
              assert config['attribute_bundle'].present?
            end

            # rubocop:disable Lint/ParenthesesAsGroupedExpression
            it 'should have only certain values' do
              next unless config['attribute_bundle']
              allowed_attributes = %w[email first_name middle_name
                                      last_name dob ssn address1 address2
                                      city state zipcode phone]
              assert (config['attribute_bundle'] - allowed_attributes).empty?
            end
            # rubocop:enable Lint/ParenthesesAsGroupedExpression
          end
        end
      end

      describe 'if the service provider uses SAML protocol' do
        next unless config['protocol'] == 'saml'

        it 'should have an acs_url value' do
          assert config['acs_url'].present?
        end

        it 'should have a valid acs_url' do
          next unless config['acs_url'].present?

          parsed_uri = URI.parse(config['acs_url'])
          assert parsed_uri.scheme.present? && parsed_uri.host.present?
        end

        it 'should have an assertion_consumer_logout_service_url value' do
          assert config['assertion_consumer_logout_service_url'].present?
        end

        it 'should have a valid assertion_consumer_logout_service_url' do
          next unless config['assertion_consumer_logout_service_url'].present?

          parsed_uri =
            URI.parse(config['assertion_consumer_logout_service_url'])
          assert parsed_uri.scheme.present? && parsed_uri.host.present?
        end
      end

      describe 'if the service provider uses OIDC protocol' do
        next unless config['protocol'] == 'oidc'

        it 'should have redirect_uris' do
          assert config['redirect_uris'].present?
        end

        it 'should have valid redirect_uris' do
          next unless config['redirect_uris'].present?

          config['redirect_uris'].each do |uri|
            parsed_uri = URI.parse(uri)
            assert parsed_uri.scheme.present? && parsed_uri.host.present?
          end
        end
      end

      # rubocop:disable Lint/ParenthesesAsGroupedExpression
      it 'should have valid definition of help text if there is one' do
        next unless config['help_text'].present?

        assert (config['help_text'].keys - %w[en es fr]).empty?
        config['help_text'].each do |locale|
          assert (locale.last.keys - %w[forgot_password sign_up sign_in]).empty?
        end
      end
      # rubocop:enable Lint/ParenthesesAsGroupedExpression
    end
  end
end
# rubocop:enable Metrics/BlockLength

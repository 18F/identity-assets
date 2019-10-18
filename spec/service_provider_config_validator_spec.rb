require 'spec_helper'

config_file = File.read('config/test_service_providers.yml')
config_yaml = YAML.load(config_file)
sp = config_yaml.first
config = HashWithIndifferentAccess.new(sp.last)

describe ServiceProviderConfigValidator do
  let(:issuer) { sp.first }

  context 'when the issuer is invalid' do
    issuer = 'bad,,, issuer'

    it 'collects an error about the invalid issuer' do
      expect(collect_sp_errors(issuer, config)).to contain_exactly 'issuer must be valid'
    end
  end

  context 'when the friendly name is missing' do
    let(:bad_config) { config.update('friendly_name': '') }

    it 'collects an error about the friendly name being undefined' do
      expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'friendly_name must be defined'
    end
  end
  context 'when the agency is missing' do
    let(:bad_config) { config.update('agency': '') }


    it 'collects an error about the friendly name being undefined' do
      expect(collect_sp_errors(issuer, bad_config)).to contain_exactly 'agency must be defined'
    end
  end
end

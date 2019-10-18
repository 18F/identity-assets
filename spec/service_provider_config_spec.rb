require 'spec_helper'

config_file = File.read('config/service_providers.yml')
config_yaml = YAML.load(config_file)['production']

byebug

describe 'Service Provider config' do
  it 'should be parsable yaml' do
    expect config_yaml.present?
  end

  config_yaml.each do |sp|
    issuer = sp.first
    config = sp.last

    describe issuer.to_s do
      it 'is valid' do
        expect(collect_sp_errors(issuer, config).join("\n")).to eq ''
      end
    end
  end
end

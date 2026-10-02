# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "rodauth-api_keys"
  spec.version = "0.1.0"
  spec.authors = ["Pavel Dušánek"]
  spec.email = ["dusanek@iquest.cz"]

  spec.summary = "API keys feature for Rodauth"
  spec.description = "The api_keys feature for Rodauth lets an account create, list, and revoke API keys. A client sends an API key in the Authorization header to authenticate a request."
  spec.homepage = "https://github.com/dush/rodauth-api_keys"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3.0"
  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/dush/rodauth-api_keys"

  # Uncomment the line below to require MFA for gem pushes.
  # This helps protect your gem from supply chain attacks by ensuring
  # no one can publish a new version without multi-factor authentication.
  # See: https://guides.rubygems.org/mfa-requirement-opt-in/
  # spec.metadata["rubygems_mfa_required"] = "true"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore test/ .github/ .standard.yml AGENTS.md doc/implementation_plan.md])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "rodauth", ">= 2.48", "< 3"

  # For more information and examples about making a new gem, check out our
  # guide at: https://guides.rubygems.org/make-your-own-gem/
end

require "webrick"
require "mercenary"
require "helper"
require "openssl"
require "httpclient"
require "tmpdir"
require "thread"

class TestCommandsServe < JekyllUnitTest
  def custom_opts(what)
    @cmd.send(
      :webrick_opts, what
    )
  end

  def start_server(opts)
    @thread = Thread.new do
      Jekyll::Commands::Serve.start(opts)
    end

    sleep(0.1) until Jekyll::Commands::Serve.running?
  end

  def serve(opts)
    allow(Jekyll).to receive(:configuration).and_return(opts)
    allow(Jekyll::Commands::Build).to receive(:process)

    start_server(opts)

    opts
  end

  context "using LiveReload" do
    setup do
      @temp_dir = Dir.mktmpdir("jekyll_livereload_test")
      @destination = File.join(@temp_dir, "_site")
      Dir.mkdir(@destination) || flunk("Could not make directory #{@destination}")
      @client = HTTPClient.new
      @standard_options = {
        "port"        => 4000,
        "host"        => "localhost",
        "baseurl"     => "",
        "detach"      => false,
        "livereload"  => true,
        "source"      => @temp_dir,
        "destination" => @destination,
        "reload_port" => Jekyll::Commands::Serve.singleton_class::LIVERELOAD_PORT
      }

      site = instance_double(Jekyll::Site)
      simple_page = <<-HTML.gsub(%r!^\s*!, "")
      <!DOCTYPE HTML>
      <html lang="en-US">
      <head>
        <meta charset="UTF-8">
        <title>Hello World</title>
      </head>
      <body>
        <p>Hello!  I am a simple web page.</p>
      </body>
      </html>
      HTML

      File.open(File.join(@destination, "hello.html"), "w") do |f|
        f.write(simple_page)
      end
      allow(Jekyll::Site).to receive(:new).and_return(site)
    end

    teardown do
      capture_io do
        Jekyll::Commands::Serve.shutdown
      end
      sleep(0.1) while Jekyll::Commands::Serve.running?

      FileUtils.remove_entry_secure(@temp_dir, true)
    end

    should "serve livereload.js over HTTP on the default LiveReload port" do
      opts = serve(@standard_options)
      content = @client.get_content(
        "http://#{opts["host"]}:#{opts["reload_port"]}/livereload.js"
      )
      assert_match(%r!LiveReload.on!, content)
    end

    should "serve livereload.js over HTTPS" do
      key = File.join(File.dirname(__FILE__), "fixtures", "test.key")
      cert = File.join(File.dirname(__FILE__), "fixtures", "test.crt")

      FileUtils.cp(key, @temp_dir)
      FileUtils.cp(cert, @temp_dir)
      opts = serve(@standard_options.merge(
        "ssl_cert" => "test.crt",
        "ssl_key"  => "test.key"
      ))

      @client.ssl_config.add_trust_ca(cert)
      content = @client.get_content(
        "https://#{opts["host"]}:#{opts["reload_port"]}/livereload.js"
      )
      assert_match(%r!LiveReload.on!, content)
    end

    should "use wss when SSL options are provided" do
      key = File.join(File.dirname(__FILE__), "fixtures", "test.key")
      cert = File.join(File.dirname(__FILE__), "fixtures", "test.crt")

      FileUtils.cp(key, @temp_dir)
      FileUtils.cp(cert, @temp_dir)
      opts = serve(@standard_options.merge(
        "ssl_cert" => "test.crt",
        "ssl_key"  => "test.key"
      ))

      @client.ssl_config.add_trust_ca(cert)
      content = @client.get_content(
        "https://#{opts["host"]}:#{opts["port"]}/#{opts["baseurl"]}/hello.html"
      )
      assert_match(%r!JEKYLL_LIVERELOAD_PROTOCOL = "wss://";!, content)
    end

    should "serve nothing else over HTTP on the default LiveReload port" do
      opts = serve(@standard_options)
      res = @client.get("http://#{opts["host"]}:#{opts["reload_port"]}/")
      assert_equal(400, res.status_code)
      assert_match(%r!only serves livereload.js!, res.content)
    end

    should "insert the LiveReload script tags" do
      opts = serve(@standard_options)
      content = @client.get_content(
        "http://#{opts["host"]}:#{opts["port"]}/#{opts["baseurl"]}/hello.html"
      )
      assert_match(%r!JEKYLL_LIVERELOAD_PORT = #{opts["reload_port"]}!, content)
      assert_match(%r!JEKYLL_LIVERELOAD_PROTOCOL = "ws://"!, content)
      assert_match(%r!livereload.js\?snipver=1!, content)
      assert_match(%r!I am a simple web page!, content)
    end

    should "apply the max and min delay options" do
      opts = serve(@standard_options.merge("max_delay" => "1066", "min_delay" => "3"))
      content = @client.get_content(
        "http://#{opts["host"]}:#{opts["port"]}/#{opts["baseurl"]}/hello.html"
      )
      assert_match(%r!&amp;mindelay=3!, content)
      assert_match(%r!&amp;maxdelay=1066!, content)
    end
  end

  context "with a program" do
    setup do
      @merc = nil
      @cmd = Jekyll::Commands::Serve
      Mercenary.program(:jekyll) do |p|
        @merc = @cmd.init_with_program(
          p
        )
      end
    end

    should "label itself" do
      assert_equal(
        @merc.name, :serve
      )
    end

    should "have aliases" do
      assert_includes @merc.aliases, :s
      assert_includes @merc.aliases, :server
    end

    should "have a description" do
      refute_nil(
        @merc.description
      )
    end

    should "have an action" do
      refute_empty(
        @merc.actions
      )
    end

    should "not have an empty options set" do
      refute_empty(
        @merc.options
      )
    end

    context "with custom options" do
      should "create a default set of mimetypes" do
        refute_nil custom_opts({})[
          :MimeTypes
        ]
      end

      should "use user destinations" do
        assert_equal "foo", custom_opts({ "destination" => "foo" })[
          :DocumentRoot
        ]
      end

      should "use user port" do
        # WHAT?!?!1 Over 9000? That's impossible.
        assert_equal 9001, custom_opts({ "port" => 9001 })[
          :Port
        ]
      end

      should "use empty directory index list when show_dir_listing is true" do
        opts = { "show_dir_listing" => true }
        assert custom_opts(opts)[:DirectoryIndex].empty?
      end

      should "keep config between build and serve" do
        custom_options = {
          "config"      => %w(_config.yml _development.yml),
          "serving"     => true,
          "reload_port" => Jekyll::Commands::Serve.singleton_class::LIVERELOAD_PORT,
          "watch"       => false # for not having guard output when running the tests
        }
        allow(SafeYAML).to receive(:load_file).and_return({})
        allow(Jekyll::Commands::Build).to receive(:build).and_return("")

        expect(Jekyll::Commands::Serve).to receive(:process).with(custom_options)
        @merc.execute(:serve, { "config" => %w(_config.yml _development.yml),
                                "watch"  => false })
      end

      context "verbose" do
        should "debug when verbose" do
          assert_equal custom_opts({ "verbose" => true })[:Logger].level, 5
        end

        should "warn when not verbose" do
          assert_equal custom_opts({})[:Logger].level, 3
        end
      end

      context "enabling SSL" do
        should "raise if enabling without key or cert" do
          assert_raises RuntimeError do
            custom_opts({
              "ssl_key" => "foo"
            })
          end

          assert_raises RuntimeError do
            custom_opts({
              "ssl_key" => "foo"
            })
          end
        end

        should "allow SSL with a key and cert" do
          expect(OpenSSL::PKey::RSA).to receive(:new).and_return("c2")
          expect(OpenSSL::X509::Certificate).to receive(:new).and_return("c1")
          allow(File).to receive(:read).and_return("foo")

          result = custom_opts({
            "ssl_cert"   => "foo",
            "source"     => "bar",
            "enable_ssl" => true,
            "ssl_key"    => "bar"
          })

          assert result[:SSLEnable]
          assert_equal result[:SSLPrivateKey ], "c2"
          assert_equal result[:SSLCertificate], "c1"
        end
      end
    end
  end
end

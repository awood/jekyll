require "thread"

module Jekyll
  module Commands
    class Serve < Command
      class << self
        COMMAND_OPTIONS = {
          "ssl_cert"             => ["--ssl-cert [CERT]", "X.509 (SSL) certificate."],
          "host"                 => ["host", "-H", "--host [HOST]", "Host to bind to"],
          "open_url"             => ["-o", "--open-url", "Launch your site in a browser"],
          "detach"               => ["-B", "--detach",
            "Run the server in the background"],
          "ssl_key"              => ["--ssl-key [KEY]", "X.509 (SSL) Private Key."],
          "port"                 => ["-P", "--port [PORT]", "Port to listen on"],
          "show_dir_listing"     => ["--show-dir-listing",
            "Show a directory listing instead of loading your index file."],
          "skip_initial_build"   => ["skip_initial_build", "--skip-initial-build",
            "Skips the initial site build which occurs before the server is started."],
          "livereload"           => ["-l", "--livereload",
            "Use LiveReload to automatically refresh browsers"],
          "livereload_ignore"    => ["--livereload-ignore ignore GLOB1[,GLOB2[,...]]",
            Array,
            "Files for LiveReload to ignore. Remember to quote the values so your shell "\
            "won't expand them"],
          "livereload_min_delay" => ["--livereload-min-delay [SECONDS]",
            "Minimum reload delay"],
          "livereload_max_delay" => ["--livereload-max-delay [SECONDS]",
            "Maximum reload delay"],
          "livereload_port"      => ["--livereload-port [PORT]", Integer,
            "Port for LiveReload to listen on"]
        }.freeze

        LIVERELOAD_PORT = 35_729
        LIVERELOAD_DIR = File.join(File.dirname(__FILE__), "serve", "livereload_assets")

        #

        def init_with_program(prog)
          prog.command(:serve) do |cmd|
            cmd.description "Serve your site locally"
            cmd.syntax "serve [options]"
            cmd.alias :server
            cmd.alias :s

            add_build_options(cmd)
            COMMAND_OPTIONS.each do |key, val|
              cmd.option key, *val
            end

            cmd.action do |_, opts|
              opts["serving"] = true

              # Check to make sure the specified options make sense logically
              # before setting defaults.
              validate_options(opts)

              # watch can legitimately be `false` so don't switch to ||=
              opts["watch"] = true unless opts.key?("watch")
              opts["livereload_port"] = LIVERELOAD_PORT \
                unless opts.key?("livereload_port")

              start(opts)
            end
          end
        end

        #

        def start(opts)
          config = opts["config"]
          @reload_reactor = nil
          register_reload_hooks(opts) if opts["livereload"]
          Build.process(opts)
          opts["config"] = config
          Serve.process(opts)
        end

        #

        # rubocop:disable Metrics/AbcSize
        def process(opts)
          opts = configuration_from_options(opts)
          destination = opts["destination"]
          setup(destination)

          # Need some way of communicating between the stop and start callbacks
          @running = Queue.new

          if opts["livereload"]
            @reload_reactor.start(opts)
          end

          @server = WEBrick::HTTPServer.new(webrick_opts(opts)).tap { |o| o.unmount("") }
          @server.mount(opts["baseurl"], Servlet, destination, file_handler_opts)

          Jekyll.logger.info "Server address:", server_address(@server, opts)
          launch_browser @server, opts if opts["open_url"]
          boot_or_detach @server, opts
        end

        #

        def running?
          !(@running.nil? || @running.empty?)
        end

        #

        def shutdown
          @server.shutdown if running?
        end

        private
        # rubocop:disable Metrics/PerceivedComplexity
        def validate_options(opts)
          if opts["livereload"]
            if opts["detach"]
              Jekyll.logger.abort_with "Error:",
                "--detach and --livereload are mutually exclusive"
            end
            unless opts["watch"]
              Jekyll.logger.warn "Using --livereload without --watch defeats the purpose"\
                " of LiveReload."
            end
          elsif opts["livereload_min_delay"] ||
              opts["livereload_max_delay"]   ||
              opts["livereload_ignore"]      ||
              opts["livereload_port"]
            Jekyll.logger.warn "The --livereload-min-delay, --livereload-max-delay, "\
               "--livereload-ignore, and --livereload-port options require the "\
               "--livereload option."
          end
        end

        private
        def register_reload_hooks(opts)
          require_relative "serve/websockets"
          @reload_reactor = LiveReloadReactor.new

          Jekyll::Hooks.register(:site, :post_render) do |site|
            regenerator = Jekyll::Regenerator.new(site)
            @changed_pages = site.pages.select do |p|
              regenerator.regenerate?(p)
            end
          end

          # A note on ignoring files: LiveReload errs on the side of reloading when it
          # comes to the message it gets.  If, for example, a page is ignored but a CSS
          # file linked in the page isn't, the page will still be reloaded if the CSS
          # file is contained in the message sent to LiveReload.  Additionally, the
          # path matching is very loose so that a message to reload "/" will always
          # lead the page to reload since every page starts with "/".
          Jekyll::Hooks.register(:site, :post_write) do
            unless @changed_pages.nil? || !@reload_reactor.running?
              ignore, @changed_pages = @changed_pages.partition do |p|
                Array(opts["livereload_ignore"]).any? do |filter|
                  File.fnmatch(filter, Jekyll.sanitized_path(p.relative_path))
                end
              end
              Jekyll.logger.debug "LiveReload:", "Ignoring #{ignore.map(&:relative_path)}"
              @reload_reactor.reload(@changed_pages)
            end
            @changed_pages = nil
          end
        end

        # Do a base pre-setup of WEBRick so that everything is in place
        # when we get ready to party, checking for an setting up an error page
        # and making sure our destination exists.

        private
        def setup(destination)
          require_relative "serve/servlet"

          FileUtils.mkdir_p(destination)
          if File.exist?(File.join(destination, "404.html"))
            WEBrick::HTTPResponse.class_eval do
              def create_error_page
                @header["Content-Type"] = "text/html; charset=UTF-8"
                @body = IO.read(File.join(@config[:DocumentRoot], "404.html"))
              end
            end
          end
        end

        #

        private
        # rubocop:disable Metrics/MethodLength
        def webrick_opts(opts)
          opts = {
            :JekyllOptions      => opts,
            :DoNotReverseLookup => true,
            :MimeTypes          => mime_types,
            :DocumentRoot       => opts["destination"],
            :StartCallback      => start_callback(opts["detach"]),
            :StopCallback       => stop_callback(opts["detach"]),
            :BindAddress        => opts["host"],
            :Port               => opts["port"],
            :DirectoryIndex     => %W(
              index.htm
              index.html
              index.rhtml
              index.cgi
              index.xml
            )
          }

          opts[:DirectoryIndex] = [] if opts[:JekyllOptions]["show_dir_listing"]

          enable_ssl(opts)
          enable_logging(opts)
          opts
        end

        # Recreate NondisclosureName under utf-8 circumstance

        private
        def file_handler_opts
          WEBrick::Config::FileHandler.merge({
            :FancyIndexing     => true,
            :NondisclosureName => [
              ".ht*", "~*"
            ]
          })
        end

        #

        private
        def server_address(server, opts)
          format("%{prefix}://%{address}:%{port}%{baseurl}", {
            :prefix  => server.config[:SSLEnable] ? "https" : "http",
            :baseurl => opts["baseurl"] ? "#{opts["baseurl"]}/" : "",
            :address => server.config[:BindAddress],
            :port    => server.config[:Port]
          })
        end

        #

        private
        def launch_browser(server, opts)
          address = server_address(server, opts)
          return system "start", address if Utils::Platforms.windows?
          return system "xdg-open", address if Utils::Platforms.linux?
          return system "open", address if Utils::Platforms.osx?
          Jekyll.logger.error "Refusing to launch browser; " \
            "Platform launcher unknown."
        end

        # Keep in our area with a thread or detach the server as requested
        # by the user.  This method determines what we do based on what you
        # ask us to do.

        private
        def boot_or_detach(server, opts)
          if opts["detach"]
            pid = Process.fork do
              server.start
            end

            Process.detach(pid)
            Jekyll.logger.info "Server detached with pid '#{pid}'.", \
              "Run `pkill -f jekyll' or `kill -9 #{pid}' to stop the server."
          else
            t = Thread.new { server.start }
            trap("INT") { server.shutdown }
            t.join
          end
        end

        # Make the stack verbose if the user requests it.

        private
        def enable_logging(opts)
          opts[:AccessLog] = []
          level = WEBrick::Log.const_get(opts[:JekyllOptions]["verbose"] ? :DEBUG : :WARN)
          opts[:Logger] = WEBrick::Log.new($stdout, level)
        end

        # Add SSL to the stack if the user triggers --enable-ssl and they
        # provide both types of certificates commonly needed.  Raise if they
        # forget to add one of the certificates.

        private
        def enable_ssl(opts)
          return if !opts[:JekyllOptions]["ssl_cert"] && !opts[:JekyllOptions]["ssl_key"]
          if !opts[:JekyllOptions]["ssl_cert"] || !opts[:JekyllOptions]["ssl_key"]
            # rubocop:disable Style/RedundantException
            raise RuntimeError, "--ssl-cert or --ssl-key missing."
          end
          require "openssl"
          require "webrick/https"

          Jekyll.logger.info "LiveReload:", "Serving over SSL/TLS.  If you are using a "\
            "certificate signed by an unknown CA, you will need to add an exception "\
            "for #{opts[:JekyllOptions]["host"]} on ports "\
            "#{opts[:JekyllOptions]["port"]} and "\
            "#{opts[:JekyllOptions]["livereload_port"]}"

          source_key = Jekyll.sanitized_path(opts[:JekyllOptions]["source"], \
                    opts[:JekyllOptions]["ssl_key" ])
          source_certificate = Jekyll.sanitized_path(opts[:JekyllOptions]["source"], \
                    opts[:JekyllOptions]["ssl_cert"])
          opts[:SSLCertificate] =
            OpenSSL::X509::Certificate.new(File.read(source_certificate))
          opts[:SSLPrivateKey ] = OpenSSL::PKey::RSA.new(File.read(source_key))
          opts[:SSLEnable] = true
        end

        private
        def start_callback(detached)
          unless detached
            proc do
              @running << "."
              Jekyll.logger.info "Server running...", "press ctrl-c to stop."
            end
          end
        end

        private
        def stop_callback(detached)
          unless detached
            proc do
              @reload_reactor.stop unless @reload_reactor.nil?
              @running.clear
            end
          end
        end

        private
        def mime_types
          file = File.expand_path("../mime.types", File.dirname(__FILE__))
          WEBrick::HTTPUtils.load_mime_types(file)
        end
      end
    end
  end
end

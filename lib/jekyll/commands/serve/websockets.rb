require "json"
require "em-websocket"
require "http/parser"

module Jekyll
  module Commands
    class Serve
      # The LiveReload protocol requires the server to serve livereload.js over HTTP
      # despite the fact that the protocol itself uses WebSockets.  This custom connection
      # class addresses the dual protocols that the server needs to understand.
      class HttpAwareConnection < EventMachine::WebSocket::Connection
        attr_reader :reload_file

        def initialize(opts)
          em_opts = {}
          @ssl_enabled = opts["ssl_cert"] && opts["ssl_key"]
          if @ssl_enabled
            em_opts[:tls_options] = {
              :private_key_file => Jekyll.sanitized_path(opts["source"], opts["ssl_key"]),
              :cert_chain_file  => Jekyll.sanitized_path(opts["source"], opts["ssl_cert"])
            }
            em_opts[:secure] = true
          end

          # This is too noisy even for --verbose, but uncomment if you need it for
          # a specific WebSockets issue
          # em_opts[:debug] = true

          super(em_opts)

          @reload_file = File.join(Serve.singleton_class::LIVERELOAD_DIR, "livereload.js")
        end

        # rubocop:disable Metrics/MethodLength
        # rubocop:disable Metrics/AbcSize
        def dispatch(data)
          parser = Http::Parser.new
          parser << data

          # WebSockets requests will have a Connection: Upgrade header
          if parser.http_method != "GET" || parser.upgrade?
            super
          elsif parser.request_url =~ %r!^\/livereload.js!
            headers = [
              "HTTP/1.1 200 OK",
              "Content-Type: application/javascript",
              "Content-Length: #{File.size(reload_file)}",
              "",
              ""
            ].join("\r\n")
            send_data(headers)
            stream_file_data(reload_file).callback do
              close_connection_after_writing
            end
          else
            body = "This port only serves livereload.js over HTTP.\n"
            headers = [
              "HTTP/1.1 400 Bad Request",
              "Content-Type: text/plain",
              "Content-Length: #{body.bytesize}",
              "",
              ""
            ].join("\r\n")
            send_data(headers)
            send_data(body)
            close_connection_after_writing
          end
        end
      end

      class LiveReloadReactor
        attr_reader :thread

        def initialize
          @thread = nil
          @websockets = []
          @connections_count = 0
        end

        def stop
          Jekyll.logger.debug("LiveReload Server:", "halted")
          @thread.kill unless @thread.nil?
        end

        def running?
          !@thread.nil? && @thread.alive?
        end

        def start(opts)
          @thread = Thread.new do
            # Use epoll if the kernel supports it
            EM.epoll
            EM.run do
              EM.error_handler do |e|
                log_error(e.message)
              end

              EM.start_server(
                opts["host"],
                opts["livereload_port"],
                HttpAwareConnection,
                opts
              ) do |ws|

                ws.onopen do |handshake|
                  connect(ws, handshake)
                end

                ws.onclose do
                  disconnect(ws)
                end

                ws.onmessage do |msg|
                  print_message(msg)
                end

                ws.onerror do |error|
                  log_error(error)
                end
              end
              Jekyll.logger.info(
                "LiveReload address:", "#{opts["host"]}:#{opts["livereload_port"]}"
              )
            end
          end
        end

        # For a description of the protocol see
        # http://feedback.livereload.com/knowledgebase/articles/86174-livereload-protocol
        def reload(pages)
          pages.each do |p|
            msg = {
              :command => "reload",
              :path    => p.url,
              :liveCSS => true
            }

            Jekyll.logger.debug("LiveReload:", "Reloading #{p.url}")
            Jekyll.logger.debug(JSON.dump(msg))
            @websockets.each do |ws|
              ws.send(JSON.dump(msg))
            end
          end
        end

        private
        def connect(ws, handshake)
          @connections_count += 1
          if @connections_count == 1
            message = "Browser connected"
            message << " over SSL/TLS" if handshake.secure?
            Jekyll.logger.info("LiveReload:", message)
          end
          ws.send(
            JSON.dump(
              :command    => "hello",
              :protocols  => ["http://livereload.com/protocols/official-7"],
              :serverName => "jekyll"
            )
          )

          @websockets << ws
        end

        private
        def disconnect(ws)
          @websockets.delete(ws)
        end

        private
        def print_message(json_message)
          msg = JSON.parse(json_message)
          # Not sure what the 'url' command even does in LiveReload.  The spec is silent
          # on its purpose.
          if msg["command"] == "url"
            Jekyll.logger.info("LiveReload:", "Browser URL: #{msg["url"]}")
          end
        end

        private
        def log_error(message)
          Jekyll.logger.warn(
            "LiveReload experienced an error. "\
            "Run with --verbose for more information."
          )
          Jekyll.logger.debug("LiveReload Error:", message)
        end
      end
    end
  end
end

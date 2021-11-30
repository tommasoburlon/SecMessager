CXX = g++
CXXLIBS = -lpthread -lm -lcrypto
CXXFLAGS = -Wall -O3 -fshort-enums

HDRDIR = include
SRCDIR = src
TSTDIR = test
BINDIR = bin
OBJDIR = build
EXPDIR = samples
USRDIR = $(EXPDIR)/users
SRVDIR = $(EXPDIR)/server
KEYDIR = $(SRVDIR)/pubkeys

#source file for non-target object
SOURCE = net/messages \
	net/SocketWrapper \
	crypto/Crypto \
	server/MessageQueue \
	server/ThreadHandler \
	utils \

#target files
CLIENT = client/client
SERVER = server/server

TARGET := $(CLIENT) \
	$(SERVER) \

#source + target file with cpp extension
CXXSRC := $(addsuffix .cpp, $(addprefix $(SRCDIR)/, $(SOURCE))) \
	$(addsuffix .cpp, $(addprefix $(SRCDIR)/, $(TARGET)))

#binary files
BINCLIENT := $(addprefix $(BINDIR)/, $(CLIENT))
BINSERVER := $(addprefix $(BINDIR)/, $(SERVER))
BINTARGET := $(addprefix $(BINDIR)/, $(TARGET))

#all the header files inside the project
HDRFILES  := $(shell find . -name "*.h")
OBJSOURCE := $(addsuffix .o, $(addprefix $(OBJDIR)/, $(SOURCE)))
OBJTARGET := $(addsuffix .o, $(addprefix $(OBJDIR)/, $(TARGET)))

target: $(BINTARGET)

$(BINDIR)/%: $(OBJDIR)/%.o $(OBJSOURCE) $(HDRFILES)
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -I $(HDRDIR) -o $@ $(filter %.o,$^) $(CXXLIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp $(HDRFILES)
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -I $(HDRDIR) -c $< -o $@ $(CXXLIBS)

clean:
	$(RM) -r $(OBJDIR) $(BINDIR) $(EXPDIR)

server: target
	mkdir -p $(SRVDIR)
	mkdir -p $(KEYDIR)
	cp $(BINSERVER) $(SRVDIR)/server

	#generate the certification authority key and certificate
	openssl req -nodes -x509 -newkey rsa:4096 -keyout $(EXPDIR)/certCAkey.pem -subj "/C=IT/ST=Italy/L=Pisa/O=CyberCompany/CN=MainAuthority.com" -out $(SRVDIR)/certCA.pem -days 365

	#generate a CSR request for the certification authority
	openssl req -nodes -new -newkey rsa:4096 -subj "/C=IT/ST=Italy/L=Pisa/O=CyberCompany/CN=ChatServer.com" -out $(SRVDIR)/server.csr -keyout $(SRVDIR)/keyServer.pem

	#the certification authority sign the server sertificate
	openssl x509 -req -in $(SRVDIR)/server.csr -CA $(SRVDIR)/certCA.pem -CAkey $(EXPDIR)/certCAkey.pem -CAcreateserial -out $(SRVDIR)/certServer.pem

	openssl ecparam -name brainpoolP512r1 -genkey -outform PEM -out $(SRVDIR)/ECprvkey.pem
	openssl ec -in $(SRVDIR)/ECprvkey.pem -pubout -out $(SRVDIR)/ECpubkey.pem

	#removes the server request
	$(RM) $(SRVDIR)/server.csr

user: server

	#generate users
	for username in $(ARGS) ; do \
		mkdir -p $(USRDIR)/$$username; \
		cp $(BINCLIENT) $(USRDIR)/$$username/client; \
		openssl genpkey -out $(USRDIR)/$$username/prvkey.pem -outform PEM -aes256 -pass pass:12345 -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP512r1; \
		openssl ec -in $(USRDIR)/$$username/prvkey.pem -pubout -passin pass:12345 -out $(KEYDIR)/$$username.pem; \
		cp $(SRVDIR)/certCA.pem $(USRDIR)/$$username/certCA.pem; \
	done;


.SECONDARY: $(OBJSOURCE) $(OBJTARGET)

.PHONY: clean target user

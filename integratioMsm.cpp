#include <iostream>
// back-end
#include <boost/msm/back/state_machine.hpp>
//front-end
#include <boost/msm/front/state_machine_def.hpp>
// libcrafter
#include <crafter.h>
// Boost Logging
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>

namespace logging = boost::log;

using namespace Crafter;

namespace msm = boost::msm;
namespace mpl = boost::mpl;

void pktHandler(Packet* sniff_packet, void* user);
std::string flags(TCP t);
std::string flags(TCP* t);

std::string iface = "lo";

namespace {

	// events
	struct syn {
		Packet* p;
		syn(Packet* pkt) : p(pkt) {}
	};
	struct ack {
		Packet* p;
		ack(Packet* pkt) : p(pkt) {}
	};
	struct psh {
		Packet* p;
		psh(Packet* pkt) : p(pkt) {}
	};
	struct rst {
		Packet* p;
		rst(Packet* pkt) : p(pkt) {}
	};
    struct fin_ack {
        Packet* p;
        fin_ack(Packet* pkt) : p(pkt) {}
    };

	// front-end
	struct integratio_ : public msm::front::state_machine_def<integratio_>
	{
        // next packet to be sent
        Packet* pkt_s;
        // last packet received
        Packet* pkt_r;
        // Used to restric packet analisys to pkt coming from outside.
        // the issue happened when working on local interface
        // outgoing packet were chacked as incoming.
        // TODO Need to check if possible to change Sniff() filter
        // at runtime.
        int streamId = -1;
        Sniffer* sniff;

		// Entry and exit actions for the whole state machine
		template <class Event, class FSM>
		void on_entry(Event const&, FSM&)
		{
            BOOST_LOG_TRIVIAL(debug) << "entering: Integratio";
            BOOST_LOG_TRIVIAL(debug) << "[INTEGRATIO] Initializing internal tcp and ip layers";

        	// Initialize the TCP and IP layer next to be sent

            pkt_s = new Packet();
            pkt_r = new Packet();

            pkt_s->PushLayer( new IP() );
            pkt_s->PushLayer( new TCP() );
            pkt_s->PushLayer( new RawLayer() );

            pkt_s->GetLayer<TCP>()->SetSeqNumber(31331);

            sniff = new Sniffer("tcp and port 80 and (src 192.168.178.37 or src 192.168.178.89 or src 127.0.0.1)", iface, pktHandler);

            BOOST_LOG_TRIVIAL(debug) << "[INTEGRATIO] " << "((" << pkt_s->GetLayer<TCP>()->GetSeqNumber() << "))";

		}

		template <class Event, class FSM>
		void on_exit(Event const&, FSM&)
		{
            BOOST_LOG_TRIVIAL(debug) << "exiting: Integratio";
		}

		// FSM States
		struct LISTEN : public msm::front::state<> {
			template <class Event,class FSM>
            void on_entry(Event const&,FSM& i) {
            	BOOST_LOG_TRIVIAL(debug) << "entering: LISTEN";
                BOOST_LOG_TRIVIAL(debug) << "[INTEGRATIO] " << "((" << i.pkt_s->GetLayer<TCP>()->GetSeqNumber() << "))";
            }
            template <class Event,class FSM>
            void on_exit(Event const&,FSM& i) {
            	BOOST_LOG_TRIVIAL(debug) << "leaving: LISTEN (assigning pkt_s)";
                i.pkt_s->GetLayer<TCP>()->SetSrcPort( i.pkt_r->GetLayer<TCP>()->GetDstPort() );
                i.pkt_s->GetLayer<TCP>()->SetDstPort( i.pkt_r->GetLayer<TCP>()->GetSrcPort() );

                i.pkt_s->GetLayer<IP>()->SetDestinationIP( i.pkt_r->GetLayer<IP>()->GetSourceIP() );
                i.pkt_s->GetLayer<IP>()->SetSourceIP( i.pkt_r->GetLayer<IP>()->GetDestinationIP() );

                i.pkt_s->GetLayer<TCP>()->SetAckNumber( i.pkt_r->GetLayer<TCP>()->GetSeqNumber() + 1 );
            }
		};
		struct SYN_RCVD : public msm::front::state<> {
			template <class Event,class FSM>
            void on_entry(Event const&,FSM& i) {
            	BOOST_LOG_TRIVIAL(debug) << "entering: SYN_RCVD";
                BOOST_LOG_TRIVIAL(debug) << "[SYN_RCVD][on_entry] " << "((" << i.pkt_s->GetLayer<IP>()->GetDestinationIP() << "))";
              
            }
            template <class Event,class FSM>
            void on_exit(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "leaving: SYN_RCVD";
            }
		};
		struct ESTABLISHED : public msm::front::state<> {
			template <class Event,class FSM>
            void on_entry(Event const&,FSM& i) {
            	BOOST_LOG_TRIVIAL(debug) << "entering: ESTABLISHED";
            }
            template <class Event,class FSM>
            void on_exit(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "leaving: ESTABLISHED";
            }
		};
		struct FIN_WAIT_1 : public msm::front::state<> {
			template <class Event,class FSM>
            void on_entry(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "entering: FIN_WAIT_1";
            }
            template <class Event,class FSM>
            void on_exit(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "leaving: FIN_WAIT_1";
            }
		};
		struct TIME_WAIT : public msm::front::state<> {
			template <class Event,class FSM>
            void on_entry(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "entering: TIME_WAIT";
            }
            template <class Event,class FSM>
            void on_exit(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "leaving: TIME_WAIT";
            }
		};
		struct CLOSING : public msm::front::state<> {
			template <class Event,class FSM>
            void on_entry(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "entering: CLOSING";
            }
            template <class Event,class FSM>
            void on_exit(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "leaving: CLOSING";
            }
		};
		struct CLOSED : public msm::front::state<> {
			template <class Event,class FSM>
            void on_entry(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "entering: CLOSED";
            }
            template <class Event,class FSM>
            void on_exit(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "leaving: CLOSED";
            }
		};
		struct SYN_SENT : public msm::front::state<> {
			template <class Event,class FSM>
            void on_entry(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "entering: SYN_SENT";
            }
            template <class Event,class FSM>
            void on_exit(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "leaving: SYN_SENT";
            }
		};
		struct CLOSE_WAIT : public msm::front::state<> {
			template <class Event,class FSM>
            void on_entry(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "entering: CLOSE_WAIT";
            }
            template <class Event,class FSM>
            void on_exit(Event const&,FSM& i) {
            	i.streamId = -1;
                i.sniff->SetFilter("tcp and port 80 and (src 192.168.178.37 or src 192.168.178.89 or src 127.0.0.1)");
                BOOST_LOG_TRIVIAL(debug) << "leaving: CLOSE_WAIT";

            }
		};
		struct LAST_ACK : public msm::front::state<> {
			template <class Event,class FSM>
            void on_entry(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "entering: LAST_ACK";
            }
            template <class Event,class FSM>
            void on_exit(Event const&,FSM& ) {
            	BOOST_LOG_TRIVIAL(debug) << "leaving: LAST_ACK";
            }
		};

		// Define initial state
		typedef LISTEN initial_state;

		// transition actions
        void sendSynAck(syn const& evt) {
        	BOOST_LOG_TRIVIAL(debug) << "integratio::sendSynAck";
            BOOST_LOG_TRIVIAL(debug) << "[sendSynAck()] " << "((dport: " << pkt_s->GetLayer<TCP>()->GetDstPort() << "))";
            BOOST_LOG_TRIVIAL(debug) << "[sendSynAck()] " << "((sport: " << pkt_s->GetLayer<TCP>()->GetSrcPort() << "))";
            BOOST_LOG_TRIVIAL(debug) << "[sendSynAck()] " << "((dst: " << pkt_s->GetLayer<IP>()->GetDestinationIP() << "))";
            BOOST_LOG_TRIVIAL(debug) << "[sendSynAck()] " << "((src: " << pkt_s->GetLayer<IP>()->GetSourceIP() << "))";
            pkt_s->GetLayer<TCP>()->SetFlags(TCP::SYN | TCP::ACK);
            BOOST_LOG_TRIVIAL(debug) << "[sendSynAck()] " << "((" << flags( pkt_s->GetLayer<TCP>() ) << "))";
            // pkt_s->PushLayer(ip_layer_s);
            // pkt_s->PushLayer(tcp_layer_s);
        	pkt_s->Send(iface);

        }
        void sendData(psh const&)    {
        	BOOST_LOG_TRIVIAL(debug) << "[ESTABLISHED] sendData";

            std::string body = "Zeta spacca i culi!!";
            int size = body.size();
            std::string payload =   "HTTP/1.1 200 OK\r\nDate: Sat, 27 Aug 2016 18:51:19 GMT\r\nContent-length: " \
                                    + std::to_string(size) + "\r\nServer: Apache/2.4.10 (Unix)\r\n\r\n" + body;

            pkt_s->GetLayer<RawLayer>()->SetPayload(payload.c_str());
            pkt_s->GetLayer<TCP>()->SetFlags(TCP::ACK);
            pkt_s->Send(iface);

        }

        void sendFinAck(fin_ack const&)    {
            BOOST_LOG_TRIVIAL(debug) << "[CLOSE_WAIT] sendData";
            pkt_s->GetLayer<RawLayer>()->SetPayload("");
            pkt_s->GetLayer<TCP>()->SetFlags(TCP::FIN | TCP::ACK);
            pkt_s->GetLayer<TCP>()->SetAckNumber( pkt_s->GetLayer<TCP>()->GetAckNumber() + 1 );
            pkt_s->Send(iface);

        }

        // Guard can be defined as bool function
        //
        // we do not need them here


        // this typedef is simply to make more readable the transition table
        typedef integratio_ i;

        // Transition table for Integratio
        // TODO From CLOSE_WAIT we go back to LISTEN instead of CLOSED

        /*
            row takes 5 arguments: start state, event, target state, action and guard.
            a_row (“a” for action) allows defining only the action and omit the guard condition.
            g_row (“g” for guard) allows omitting the action behavior and defining only the guard.
            _row allows omitting action and guard.
        */
        struct transition_table : mpl::vector<
            //    Start        	Event      	Next          	Action            Guard
            //  +---------+-------------+---------+---------------------+----------------------+
          a_row < LISTEN,	   	syn      	, SYN_RCVD , 	&i::sendSynAck                         >,
           _row < SYN_RCVD, 	ack 		, ESTABLISHED 				                           >,
          a_row < ESTABLISHED, 	psh 		, ESTABLISHED , &i::sendData                           >,
          a_row < ESTABLISHED,  fin_ack     , CLOSE_WAIT  , &i::sendFinAck                         >,
           _row < CLOSE_WAIT,   ack         , LISTEN                                               >
            //  +---------+-------------+---------+---------------------+----------------------+
        > {};
        // Replaces the default no-transition response.
        template <class FSM,class Event>
        void no_transition(Event const& e, FSM&,int state)
        {
            BOOST_LOG_TRIVIAL(debug) << "no transition from state " << state << " on event " << typeid(e).name();
        }
    };

    // Pick a back-end
	typedef msm::back::state_machine<integratio_> integratio;

    // Testing utilities.
    //
    static char const* const state_names[] = { "LISTEN", "SYN_RCVD", "ESTABLISHED" };
    void pstate(integratio const& i)
    {
        BOOST_LOG_TRIVIAL(debug) << " -> " << state_names[i.current_state()[0]];
    }

    void test() {
    	integratio i;

    	i.start();
    	i.sniff->Capture(-1, &i);


    	// i.process_event( syn() ); pstate(i);
    	// i.process_event( ack() ); pstate(i);

    }
}

// Define the libcrafter packetHandler
void pktHandler(Packet* sniff_packet, void* user) {
	
	// Casting the user to have a reference to integratio state machine
	/*
	*	TODO Review performance with less de-reference
	*/
    integratio* i = static_cast<integratio*>(user);

    // sniff_packet->Print();

    RawLayer* payload = GetRawLayer(*sniff_packet);
    i->pkt_r = sniff_packet;


    // if the client ACKs something, we update our SEQ
    if( sniff_packet->GetLayer<TCP>()->GetAckNumber() > i->pkt_s->GetLayer<TCP>()->GetSeqNumber() ){
        if( i->streamId == -1)
            i->pkt_s->GetLayer<TCP>()->SetSeqNumber( sniff_packet->GetLayer<TCP>()->GetAckNumber() );
        else {
            if( sniff_packet->GetLayer<TCP>()->GetSrcPort() == i->streamId ) {
                i->pkt_s->GetLayer<TCP>()->SetSeqNumber( sniff_packet->GetLayer<TCP>()->GetAckNumber() );
            }
        }
            
    }

    BOOST_LOG_TRIVIAL(debug) << "[PKT RECV] streamdId: " << i->streamId;

    if ( payload && sniff_packet->GetLayer<TCP>()->GetSrcPort() == i->streamId ) {
        i->pkt_s->GetLayer<TCP>()->SetAckNumber( i->pkt_s->GetLayer<TCP>()->GetAckNumber() + payload->GetSize() );
    }
    
    std::string x = flags( *i->pkt_r->GetLayer<TCP>() );

    BOOST_LOG_TRIVIAL(debug) << "[RCV] [" << i->pkt_r->GetLayer<IP>()->GetSourceIP() << ": " <<  i->pkt_r->GetLayer<TCP>()->GetSrcPort() << " (" << x << ")]";

    if(i->pkt_r->GetLayer<TCP>()->GetSYN()) {
        if( i->streamId == -1 ) {
            i->streamId = sniff_packet->GetLayer<TCP>()->GetSrcPort();
            i->sniff->SetFilter("tcp and port 80 and (src 192.168.178.37 or src 192.168.178.89 or src 127.0.0.1) and tcp src port " \
                                + std::to_string( i->streamId ));
        }
    	i->process_event( syn(sniff_packet) );
    }

	if(i->pkt_r->GetLayer<TCP>()->GetACK()) {
    	i->process_event( ack(sniff_packet) );
    }    
    
    if(i->pkt_r->GetLayer<TCP>()->GetPSH()) {
    	i->process_event( psh(sniff_packet) );
    }

    if( i->pkt_r->GetLayer<TCP>()->GetFIN() && i->pkt_r->GetLayer<TCP>()->GetACK()) {
        i->process_event( fin_ack(sniff_packet) );
    }

}

std::string flags(TCP t){
    std::bitset<8> x( t.GetFlags() );

    std::string f = "";

    if (x[0]) {
        f += 'F';
    }
    if (x[1]) {
        f += 'S';
    }
    if (x[2]) {
        f += 'R';
    }
    if (x[3]) {
        f += 'P';
    }
    if (x[4]) {
        f += 'A';
    }
    if (x[5]) {
        f += 'U';
    }
    if (x[6]) {
        f += 'E';
    }
    if (x[7]) {
        f += 'C';
    }

    return f;
}


std::string flags(TCP* t){
    std::bitset<8> x( t->GetFlags() );

    std::string f = "";

    if (x[0]) {
        f += 'F';
    }
    if (x[1]) {
        f += 'S';
    }
    if (x[2]) {
        f += 'R';
    }
    if (x[3]) {
        f += 'P';
    }
    if (x[4]) {
        f += 'A';
    }
    if (x[5]) {
        f += 'U';
    }
    if (x[6]) {
        f += 'E';
    }
    if (x[7]) {
        f += 'C';
    }

    return f;
}


// Initialize the logging filter. 
// trace, debug, info, warning, error, fatal
void init()
{
    logging::core::get()->set_filter
    (
        logging::trivial::severity >= logging::trivial::debug
    );
}

int main( int argc, char *argv[] ) {
    if ( argc == 2 ) {
        iface = argv[1];
    }

    init();
	test();
	return 0;
}

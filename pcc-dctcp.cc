/*
 * Copyright (c) 2013 ResiliNets, ITTC, University of Kansas
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Justin P. Rohrer, Truc Anh N. Nguyen <annguyen@ittc.ku.edu>, Siddharth Gangadhar
 * <siddharth@ittc.ku.edu>
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  https://resilinets.org/
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 *
 * "TCP Westwood(+) Protocol Implementation in ns-3"
 * Siddharth Gangadhar, Trúc Anh Ngọc Nguyễn , Greeshma Umapathi, and James P.G. Sterbenz,
 * ICST SIMUTools Workshop on ns-3 (WNS3), Cannes, France, March 2013
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/enum.h"
#include "ns3/error-model.h"
#include "ns3/event-id.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/tcp-header.h"
#include "ns3/traffic-control-module.h"
#include "ns3/udp-header.h"

#include <fstream>
#include <iostream>
#include <string>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("pccDctcp");

static std::map<uint32_t, bool> firstCwnd;                      //!< First congestion window.
static std::map<uint32_t, bool> firstSshThr;                    //!< First SlowStart threshold.
static std::map<uint32_t, bool> firstRtt;                       //!< First RTT.
static std::map<uint32_t, bool> firstRto;                       //!< First RTO.
static std::map<uint32_t, Ptr<OutputStreamWrapper>> cWndStream; //!< Congstion window outut stream.
static std::map<uint32_t, Ptr<OutputStreamWrapper>>
    ssThreshStream; //!< SlowStart threshold outut stream.
static std::map<uint32_t, Ptr<OutputStreamWrapper>> rttStream;      //!< RTT outut stream.
static std::map<uint32_t, Ptr<OutputStreamWrapper>> rtoStream;      //!< RTO outut stream.
static std::map<uint32_t, Ptr<OutputStreamWrapper>> nextTxStream;   //!< Next TX outut stream.
static std::map<uint32_t, Ptr<OutputStreamWrapper>> nextRxStream;   //!< Next RX outut stream.
static std::map<uint32_t, Ptr<OutputStreamWrapper>> inFlightStream; //!< In flight outut stream.
static std::map<uint32_t, uint32_t> cWndValue;                      //!< congestion window value.
static std::map<uint32_t, uint32_t> ssThreshValue;                  //!< SlowStart threshold value.

/**
 * Get the Node Id From Context.
 *
 * \param context The context.
 * \return the node ID.
 */
static uint32_t
GetNodeIdFromContext(std::string context)
{
    std::size_t const n1 = context.find_first_of('/', 1);
    std::size_t const n2 = context.find_first_of('/', n1 + 1);
    return std::stoul(context.substr(n1 + 1, n2 - n1 - 1));
}

/**
 * Congestion window tracer.
 *
 * \param context The context.
 * \param oldval Old value.
 * \param newval New value.
 */
static void
CwndTracer(std::string context, uint32_t oldval, uint32_t newval)
{
    uint32_t nodeId = GetNodeIdFromContext(context);

    if (firstCwnd[nodeId])
    {
        *cWndStream[nodeId]->GetStream() << "0.0 " << oldval << std::endl;
        firstCwnd[nodeId] = false;
    }
    *cWndStream[nodeId]->GetStream() << Simulator::Now().GetSeconds() << " " << newval << std::endl;
    cWndValue[nodeId] = newval;

    if (!firstSshThr[nodeId])
    {
        *ssThreshStream[nodeId]->GetStream()
            << Simulator::Now().GetSeconds() << " " << ssThreshValue[nodeId] << std::endl;
    }
}

/**
 * RTT tracer.
 *
 * \param context The context.
 * \param oldval Old value.
 * \param newval New value.
 */
static void
RttTracer(std::string context, Time oldval, Time newval)
{
    uint32_t nodeId = GetNodeIdFromContext(context);

    if (firstRtt[nodeId])
    {
        *rttStream[nodeId]->GetStream() << "0.0 " << oldval.GetSeconds() << std::endl;
        firstRtt[nodeId] = false;
    }
    *rttStream[nodeId]->GetStream()
        << Simulator::Now().GetSeconds() << " " << newval.GetSeconds() << std::endl;
}

/**
 * Congestion window trace connection.
 *
 * \param cwnd_tr_file_name Congestion window trace file name.
 * \param nodeId Node ID.
 */
static void
TraceCwnd(std::string cwnd_tr_file_name, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    cWndStream[nodeId] = ascii.CreateFileStream(cwnd_tr_file_name);
    Config::Connect("/NodeList/" + std::to_string(nodeId) +
                        "/$ns3::TcpL4Protocol/SocketList/0/CongestionWindow",
                    MakeCallback(&CwndTracer));
}

/**
 * RTT trace connection.
 *
 * \param rtt_tr_file_name RTT trace file name.
 * \param nodeId Node ID.
 */
static void
TraceRtt(std::string rtt_tr_file_name, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    rttStream[nodeId] = ascii.CreateFileStream(rtt_tr_file_name);
    Config::Connect("/NodeList/" + std::to_string(nodeId) + "/$ns3::TcpL4Protocol/SocketList/0/RTT",
                    MakeCallback(&RttTracer));
}


int main(int argc, char* argv[])
{
    std::string transport_prot = "TcpDctcp";
    std::string SD_bandwidth = "1Gbps";
    std::string RR_bandwidth = "10Gbps";
    std::string delay = "0.01ms";
    bool tracing = true;
    std::string prefix_file_name = "pcc-dctcp";
    double duration = 5;
    uint32_t run = 0;
    bool flow_monitor = false;
    bool pcap = false;
    std::string queue_disc_type = "ns3::CoDelQueueDisc";
    uint16_t num_senders = 1;
    uint16_t num_receivers = 1;


    CommandLine cmd(__FILE__);
    cmd.AddValue("transport_prot",
                 "Transport protocol to use: TcpNewReno, TcpLinuxReno, "
                 "TcpHybla, TcpHighSpeed, TcpHtcp, TcpVegas, TcpScalable, TcpVeno, "
                 "TcpBic, TcpYeah, TcpIllinois, TcpWestwood, TcpWestwoodPlus, TcpLedbat, "
                 "TcpLp, TcpDctcp, TcpCubic, TcpBbr",
                 transport_prot);
    cmd.AddValue("SD_bandwidth", "S-R,R-D bandwidth", SD_bandwidth);
    cmd.AddValue("RR_bandwidth", "R-R bandwidth", RR_bandwidth);
    cmd.AddValue("delay", "Bottleneck delay", delay);
    cmd.AddValue("tracing", "Flag to enable/disable tracing", tracing);
    cmd.AddValue("prefix_name", "Prefix of output trace file", prefix_file_name);
    cmd.AddValue("duration", "Time to allow flows to run in seconds", duration);
    cmd.AddValue("run", "Run index (for setting repeatable seeds)", run);
    cmd.AddValue("flow_monitor", "Enable flow monitor", flow_monitor);
    cmd.AddValue("pcap_tracing", "Enable or disable PCAP tracing", pcap);
    cmd.AddValue("queue_disc_type",
                 "Queue disc type for gateway (e.g. ns3::CoDelQueueDisc)",
                 queue_disc_type);
    cmd.AddValue("num_senders", "Number of senders", num_senders);
    cmd.AddValue("num_receivers", "Number of receivers", num_receivers);
    cmd.Parse(argc, argv);

    transport_prot = std::string("ns3::") + transport_prot;

    SeedManager::SetSeed(1);
    SeedManager::SetRun(run);

    LogComponentEnable("OnOffApplication", LOG_LEVEL_INFO);
    LogComponentEnable("CoDelQueueDisc", LOG_LEVEL_INFO);
    LogComponentEnable("pccDctcp", LOG_LEVEL_INFO);
    

    // Set the simulation start and stop time
    double start_time = 0;
    double stop_time = start_time + duration;

    // 2 MB of TCP buffer
    Config::SetDefault("ns3::TcpSocket::RcvBufSize", UintegerValue(1 << 21));
    Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(1 << 21));

    Config::SetDefault("ns3::TcpL4Protocol::SocketType", StringValue(transport_prot));


    NodeContainer senders;
    senders.Create(num_senders);
    NodeContainer routers;
    routers.Create(2);
    NodeContainer receivers;
    receivers.Create(num_receivers);

    PointToPointHelper pointToPointSD;
    pointToPointSD.SetDeviceAttribute("DataRate", StringValue(SD_bandwidth));
    pointToPointSD.SetChannelAttribute("Delay", StringValue(delay));

    PointToPointHelper pointToPointRR;
    pointToPointRR.SetDeviceAttribute("DataRate", StringValue(RR_bandwidth));
    pointToPointRR.SetChannelAttribute("Delay", StringValue(delay));

    std::vector<NetDeviceContainer> SR;
    SR.reserve(num_senders);
    std::vector<NetDeviceContainer> RD;
    RD.reserve(num_receivers);
    NetDeviceContainer RR = pointToPointRR.Install(routers.Get(0), routers.Get(1));
    for (std::size_t i = 0; i < num_senders; i++)
    {
        SR.push_back(pointToPointSD.Install(senders.Get(i), routers.Get(0)));
    }
    for (std::size_t i = 0; i < num_senders; i++)
    {
        RD.push_back(pointToPointSD.Install(receivers.Get(i),routers.Get(1)));
    }

    InternetStackHelper stack;
    stack.InstallAll();

    TrafficControlHelper tchCoDel;
    tchCoDel.SetRootQueueDisc("ns3::CoDelQueueDisc");
    Config::SetDefault("ns3::CoDelQueueDisc::MaxSize",QueueSizeValue(QueueSize("25p")));
    Config::SetDefault("ns3::CoDelQueueDisc::UseEcn",BooleanValue(true));
    tchCoDel.Install(RR);
    for (uint32_t i = 0; i <num_senders; i++)
    {
        tchCoDel.Install(SR[i].Get(1));
    }
    for (uint32_t i = 0; i <num_receivers; i++)
    {
        tchCoDel.Install(RD[i].Get(1));
    }

    Ipv4AddressHelper address;
    std::vector<Ipv4InterfaceContainer> ipSR;
    ipSR.reserve(num_senders);
    std::vector<Ipv4InterfaceContainer> ipRD;
    ipRD.reserve(num_receivers);
    address.SetBase("192.168.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ipRR = address.Assign(RR);
    address.SetBase("10.1.1.0", "255.255.255.0");
    for (uint32_t i = 0; i <num_senders; i++)
    {
        ipSR.push_back(address.Assign(SR[i]));
        address.NewNetwork();
    }
    address.SetBase("10.2.1.0", "255.255.255.0");
    for (uint32_t i = 0; i <num_receivers; i++)
    {
        ipRD.push_back(address.Assign(RD[i]));
        address.NewNetwork();
    }

    NS_LOG_INFO("Initialize Global Routing.");
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    uint32_t groups = num_senders / num_receivers;
    std::vector<Ptr<PacketSink>> sinks;
    sinks.reserve(num_receivers);
    for (uint32_t i = 0; i < num_receivers; i++)
    {
        uint16_t port = 50000 + i;
        Address sinkLocalAddress(InetSocketAddress(Ipv4Address::GetAny(), port));
        PacketSinkHelper sinkHelper("ns3::TcpSocketFactory", sinkLocalAddress);
        ApplicationContainer sinkApp = sinkHelper.Install(receivers.Get(i));
        Ptr<PacketSink> packetSink = sinkApp.Get(0)->GetObject<PacketSink>();
        sinks.push_back(packetSink);
        sinkApp.Start(Seconds(start_time));
        sinkApp.Stop(Seconds(stop_time));

        for (uint32_t j = 0; j < groups; j++)
        {
            OnOffHelper clientHelper("ns3::TcpSocketFactory", Address());
            clientHelper.SetAttribute("OnTime",StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            clientHelper.SetAttribute("OffTime",StringValue("ns3::ConstantRandomVariable[Constant=0]"));
            clientHelper.SetAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
            clientHelper.SetAttribute("PacketSize", UintegerValue(1024));

            ApplicationContainer clientApps;
            AddressValue remoteAddress(InetSocketAddress(ipSR[i*groups+j].GetAddress(0), port));
            clientHelper.SetAttribute("Remote", remoteAddress);
            clientApps.Add(clientHelper.Install(senders.Get(i*groups+j)));
            clientApps.Start(Seconds(start_time));
            clientApps.Stop(Seconds(stop_time-1));
        }
    }

    // Set up tracing if enabled
    if (tracing)
    {
        std::ofstream ascii;
        Ptr<OutputStreamWrapper> ascii_wrap;
        ascii.open(prefix_file_name + "-ascii");
        ascii_wrap = new OutputStreamWrapper(prefix_file_name + "-ascii", std::ios::out);
        stack.EnableAsciiIpv4All(ascii_wrap);

        for (uint32_t index = 0; index < num_senders; index++)
        {
            std::string flowString;
            if (num_senders > 1)
            {
                flowString = "-flow" + std::to_string(index);
            }

            firstCwnd[index + 1] = true;
            firstSshThr[index + 1] = true;
            firstRtt[index + 1] = true;
            firstRto[index + 1] = true;

            Simulator::Schedule(Seconds(start_time+0.00001),
                                &TraceCwnd,
                                prefix_file_name + flowString + "-cwnd.data",
                                index);
            Simulator::Schedule(Seconds(start_time+0.00001),
                                &TraceRtt,
                                prefix_file_name + flowString + "-rtt.data",
                                index);
        }
    }

    if (pcap)
    {
        pointToPointSD.EnablePcapAll(prefix_file_name, true);
        pointToPointRR.EnablePcapAll(prefix_file_name, true);
    }

    // Flow monitor
    FlowMonitorHelper flowHelper;
    if (flow_monitor)
    {
        flowHelper.InstallAll();
    }

    Simulator::Stop(Seconds(stop_time) + TimeStep(1));
    NS_LOG_INFO("Start simulator.");
    Simulator::Run();

    if (flow_monitor)
    {
        flowHelper.SerializeToXmlFile(prefix_file_name + ".flowmonitor", true, true);
    }

    Simulator::Destroy();
    return 0;
}

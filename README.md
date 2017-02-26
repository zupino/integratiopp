# Integratio++

Due to performance issue with the Scapy-based initial version of Integratio, we are experimenting now a port in C++.

Currently we are using Boost::MSM as Finite State Machine framework and libcrafter for acket sniffig and crafting.
We will try different technology until we find an acceptable compromise between usability and performances.

NOTE: this repository is by no mean intended for any meaningful task rather then investigating performances of different libraries. For a usable (but slow) version of Integratio refer to the original project repository https://bitbucket.org/zupino/integratio/

To build this example, you need:

- Boost installed and compiled, including the shared libraries for logging: http://www.boost.org/doc/libs/1_63_0/libs/msm/doc/HTML/ch03s02.html

- LibCrafter installed: https://github.com/pellegre/libcrafter 

```
c++ ~/intBoost/integratioMsm.cpp -std=c++11 -DBOOST_LOG_DYN_LINK -lboost_log -lboost_log_setup -lboost_filesystem -lboost_thread -lboost_date_time -lboost_system -lpthread -lrt -lcrafter -o /home/zeta/intBoost/integratioMsm
```

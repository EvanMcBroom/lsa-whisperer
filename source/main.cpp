#include <msv1_0/args.hpp>
#include <pku2u/args.hpp>
#include <schannel/args.hpp>

int main(int argc, char** argv) {
    return (
        Msv1_0::Parse(argc, argv) ||
        Pku2u::Parse(argc, argv) ||
        Schannel::Parse(argc, argv)
        ) ? 0 : -1;
}
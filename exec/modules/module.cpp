#include "module.h"

namespace module {

void Module::check_name(const std::string & n) const{
    // check for whitespace in name
    for(char const & c : n){
        if (std::isspace(c)){
            throw std::runtime_error("Error: Whitespace found in name: " + n);
        }
    }
}

void Module::check_positional(const std::vector <std::string> & pos) const{
    // make sure there aren't duplicate positional arguements
    std::vector <std::string> pos_cp = positional;
    std::sort(pos_cp.begin(), pos_cp.end());
    for(std::string::size_type i = 1; i < pos_cp.size(); i++){
        if (pos_cp[i - 1] == pos_cp[i]){
            throw std::runtime_error("Error: Duplicate postional arguments found: " + pos_cp[i]);
        }
    }
}

void Module::check_duplicate(const Args & arg, const Flags & flag) const{
    for(std::pair <const std::string, std::pair <std::string, bool> > const & f : flag){
        if (arg.find(f.first) != args.end()){
            throw std::runtime_error("Error: Duplicate option " + f.first + " found.");
        }
    }

    for(std::pair <const std::string, std::pair <std::string, std::string> > const & a : arg){
        if (flag.find(a.first) != flags.end()){
            throw std::runtime_error("Error: Duplicate option " + a.first + " found.");
        }
    }
}

void  Module::check_run(const std::function <int(std::map <std::string, std::string> &)> & func) const{}

// unknown arguments are ignored
char * Module::parse(int argc, char * argv[],
                     std::map <std::string, std::string> & parsed_args,
                     std::map <std::string, bool>        & parsed_flags) const{
    std::vector <std::string>::size_type pos = 0;
    for(int i = 0; i < argc; i++){
        // if the first character of the argument is a dash
        if (argv[i][0] == '-'){

            // check if option is in args
            Args::const_iterator args_it = args.find(argv[i]);
            if (args_it != args.end()){
                // if no more arguments
                if ((i + 1) >= argc){
                    return argv[i];
                }

                parsed_args[args_it -> first] = argv[i + 1];
                i++;// skip value
                continue;
            }

            // check if option is in flags
            Flags::const_iterator flags_it = flags.find(argv[i]);
            if (flags_it != flags.end()){
                parsed_flags[flags_it -> first] = !flags_it -> second.second;
                continue;
            }

            // error
            return argv[i];
        }
        else{
            // set positional argument
            if (pos < positional.size()){
                // if positional argument isn't already in the arguments list
                if (parsed_args.find(positional[pos]) == parsed_args.end()){
                    parsed_args[positional[pos]] = argv[i];
                    pos++;
                }
            }
        }
    }

    return nullptr;
}

Module::Module(const Module & cmd)
    : name(cmd.name),
      positional(cmd.positional),
      args(cmd.args),
      flags(cmd.flags),
      run(cmd.run)
{}

Module::Module(Module && cmd)
    : name(std::move(cmd.name)),
      positional(std::move(cmd.positional)),
      args(std::move(cmd.args)),
      flags(std::move(cmd.flags)),
      run(std::move(cmd.run))
{}

Module::Module(const std::string                                                      & n,
               const std::vector <std::string>                                        & pos,
               const Args                                                             & arg,
               const Flags                                                            & flag,
               const std::function <int(const std::map <std::string, std::string> &,
                                        const std::map <std::string, bool>        &)> & func)

    : name(),
      positional(),
      args(),
      flags(),
      run()
{
    check_name(n);
    check_positional(pos);
    check_optional(args);
    check_optional(flags);

    check_duplicate(args, flags);

    // only set values after input passes
    name       = n;
    positional = pos;
    args       = arg;
    flags      = flag;
    run        = func;
}

Module & Module::operator=(const Module & cmd){
    name       = cmd.name;
    positional = cmd.positional;
    args       = cmd.args;
    flags      = cmd.flags;
    run        = cmd.run;
    return *this;
}

Module & Module::operator=(Module && cmd){
    name       = std::move(cmd.name);
    positional = std::move(cmd.positional);
    args       = std::move(cmd.args);
    flags      = std::move(cmd.flags);
    run        = std::move(cmd.run);
    return *this;
}

const std::string & Module::get_name() const{
    return name;
}

std::string Module::help(const std::string & indent) const{
    std::string help_str = indent + name;

    // append positional arguments
    for(std::string const & p : positional){
        help_str += " " + p;
    }

    // add "[options]" marker
    if (args.size() || flags.size()){
        help_str += " [options]\n";

        // add optional arguments
        if (args.size()){
            help_str += indent + "    Optional Arguments:\n";
            for(std::pair <const std::string, std::pair <std::string, std::string> > const & arg : args){
                help_str += indent + indent + "        " + arg.first + " " + arg.second.first + "; default value: \"" + arg.second.second + "\"\n";
            }
        }

        // add optional flags
        if (flags.size()){
            help_str += indent + "    Optional Flags:\n";
            for(std::pair <const std::string, std::pair <std::string, bool> > const & flag :flags){
                help_str += indent + indent + "        " + flag.first + " " + flag.second.first + "; default value: " + (flag.second.second?"true":"false") + "\n";
            }
        }
    }

    return help_str;
}

int Module::operator()(int argc, char * argv[]) const{
    // fill arguments with optional argument default values
    std::map <std::string, std::string> parsed_args;
    for(std::pair <const std::string, std::pair <std::string, std::string> > const & kv : args){
        parsed_args[kv.first] = kv.second.second;
    }

    // fill arguments with optional flag default values
    std::map <std::string, bool> parsed_flags;
    for(std::pair <const std::string, std::pair <std::string, bool> > const & kv : flags){
        parsed_flags[kv.first] = kv.second.second?"t":"f";
    }

    // parse input arguments
    if (parse(argc, argv, parsed_args, parsed_flags) || (run(parsed_args, parsed_flags) == -1)){
        std::cout << help() << std::endl;
        return -1;
    }

    return 0;
}

// Output data into a file, or if not possible, to std::cout
void output(const std::string & data, const std::string & filename){
    if (filename != ""){
        try{
            std::ofstream out(filename.c_str(), std::ios::binary);
            if (!out){
                throw std::runtime_error("Error: File " + filename + " could not be opened.");
            }

            out << data;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << "\n" << data << std::endl;
        }
    }
    else{
        std::cout << data << std::endl;
    }
}

}

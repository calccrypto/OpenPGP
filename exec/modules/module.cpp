#include "module.h"

namespace module {

void Module::check_names_ws() const{
    // make sure the module is callable
    if (!name.size()){
        throw std::runtime_error("Error: Empty name");
    }

    // check name of this module
    for(char const & c : name){
        if (std::isspace(c)){
            throw std::runtime_error("Error: Whitespace found in name: " + name);
        }
    }

    // check names of optional arguments
    for(std::pair <std::string const, std::pair <std::string, std::string> > const & opt : opts){
        for(char const & c : opt.first){
            if (std::isspace(c)){
                throw std::runtime_error("Error: Whitespace found in optional argument: " + opt.first);
            }
        }
    }

    // check names of flags
    for(std::pair <std::string const, std::pair <std::string, bool> > const & flag : flags){
        for(char const & c : flag.first){
            if (std::isspace(c)){
                throw std::runtime_error("Error: Whitespace found in flag: " + flag.first);
            }
        }
    }
}

void Module::check_duplicate() const{
    // make sure there aren't duplicate positional arguments
    std::vector <std::string> pos_cp = positional;
    std::sort(pos_cp.begin(), pos_cp.end());
    for(std::string::size_type i = 1; i < pos_cp.size(); i++){
        if (pos_cp[i - 1] == pos_cp[i]){
            throw std::runtime_error("Error: Duplicate postional arguments found: " + pos_cp[i]);
        }
    }

    // check for duplicate positional/optional arguments
    for(std::string const & pos : positional){
        if (opts.find(pos) != opts.end()){
            throw std::runtime_error("Error: Duplicate positional/optional argument " + pos + " found.");
        }
    }

    // check for duplicate positional arguments/flags
    for(std::string const & pos : positional){
        if (flags.find(pos) != flags.end()){
            throw std::runtime_error("Error: Duplicate positional argument/flag " + pos + " found.");
        }
    }

    // check for duplicate optional arguments/flags
    for(std::pair <std::string const, std::pair <std::string, bool> > const & flag : flags){
        if (opts.find(flag.first) != opts.end()){
            throw std::runtime_error("Error: Duplicate optional argument/flag " + flag.first + " found.");
        }
    }
}

// unknown arguments are ignored
const char * Module::parse(int argc, char * argv[],
                           std::map <std::string, std::string> & parsed_args,
                           std::map <std::string, bool>        & parsed_flags) const{

    std::vector <std::string>::size_type pos = 0;
    for(int i = 0; i < argc; i++){
        // check if option is in opts
        Opts::const_iterator opts_it = opts.find(argv[i]);
        if (opts_it != opts.end()){
            // if no more arguments
            if ((i + 1) >= argc){
                return argv[i];
            }

            parsed_args[opts_it -> first] = argv[i + 1];
            i++;// skip value
            continue;
        }

        // check if option is in flags
        Flags::const_iterator flags_it = flags.find(argv[i]);
        if (flags_it != flags.end()){
            parsed_flags[flags_it -> first] = !flags_it -> second.second;
            continue;
        }

        // assume it is a positional argument
        if (pos < positional.size()){
            parsed_args[positional[pos++]] = argv[i];
        }
    }

    if (pos < positional.size()){
        return positional[pos].c_str();
    }

    return nullptr;
}

Module::Module(const Module & cmd)
    : name(cmd.name),
      positional(cmd.positional),
      opts(cmd.opts),
      flags(cmd.flags),
      run(cmd.run)
{}

Module::Module(Module && cmd)
    : name(std::move(cmd.name)),
      positional(std::move(cmd.positional)),
      opts(std::move(cmd.opts)),
      flags(std::move(cmd.flags)),
      run(std::move(cmd.run))
{}

Module::Module(const std::string                & n,
               const std::vector <std::string>  & pos,
               const Module::Opts               & opt,
               const Module::Flags              & flag,
               const Module::Run                & func)
    : name(n),
      positional(pos),
      opts(opt),
      flags(flag),
      run(func)
{
    // throw if fail
    check_names_ws();
    check_duplicate();
}

Module & Module::operator=(const Module & cmd){
    name       = cmd.name;
    positional = cmd.positional;
    opts       = cmd.opts;
    flags      = cmd.flags;
    run        = cmd.run;
    return *this;
}

Module & Module::operator=(Module && cmd){
    name       = std::move(cmd.name);
    positional = std::move(cmd.positional);
    opts       = std::move(cmd.opts);
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
    if (opts.size() || flags.size()){
        help_str += " [options]\n";

        // add optional arguments
        if (opts.size()){
            help_str += indent + "    Optional Arguments:\n";
            for(std::pair <std::string const, std::pair <std::string, std::string> > const & opt : opts){
                help_str += indent + "        " + opt.first + " " + opt.second.first + "; default value: \"" + opt.second.second + "\"\n";
            }
        }

        // add optional flags
        if (flags.size()){
            help_str += "\n" + indent + "    Optional Flags:\n";
            for(std::pair <std::string const, std::pair <std::string, bool> > const & flag : flags){
                help_str += indent + "        " + flag.first + " " + flag.second.first + "; default value: " + (flag.second.second?"true":"false") + "\n";
            }
        }
    }
    else{
        help_str += "\n";
    }

    return help_str;
}

int Module::operator()(int argc, char * argv[], std::ostream & out, std::ostream & err) const{
    // fill arguments with optional argument default values
    std::map <std::string, std::string> parsed_args;
    for(std::pair <std::string const, std::pair <std::string, std::string> > const & opt : opts){
        parsed_args[opt.first] = opt.second.second;
    }

    // fill arguments with optional flag default values (false)
    std::map <std::string, bool> parsed_flags;
    for(std::pair <std::string const, std::pair <std::string, bool> > const & flag : flags){
        parsed_flags[flag.first] = flag.second.second;
    }

    // parse input arguments
    if (parse(argc, argv, parsed_args, parsed_flags) || (run(parsed_args, parsed_flags, out, err) == -1)){
        out << help() << std::endl;
        return -1;
    }

    return 0;
}

}

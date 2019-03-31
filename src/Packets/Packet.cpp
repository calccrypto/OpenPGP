#include "Packets/Packet.h"

#include <cstdint>

#include "Packets/Partial.h"
#include "Misc/Length.h"

namespace OpenPGP {
namespace Packet {

bool is_key_packet(const uint8_t t) {
    return (is_primary_key(t) || is_subkey(t));
}

bool is_primary_key(const uint8_t t) {
    return ((t == SECRET_KEY) ||
            (t == PUBLIC_KEY));
}

bool is_subkey(const uint8_t t) {
    return ((t == SECRET_SUBKEY) ||
            (t == PUBLIC_SUBKEY));
}

bool is_public(const uint8_t t) {
    return ((t == PUBLIC_KEY) ||
            (t == PUBLIC_SUBKEY));
}

bool is_secret(const uint8_t t) {
    return ((t == SECRET_KEY) ||
            (t == SECRET_SUBKEY));
}

bool is_user(const uint8_t t) {
    return ((t == USER_ID) ||
            (t == USER_ATTRIBUTE));
}

bool is_session_key(const uint8_t t) {
    return ((t == PUBLIC_KEY_ENCRYPTED_SESSION_KEY) ||
            (t == SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
}

bool is_sym_protected_data(const uint8_t t) {
    return ((t == SYMMETRICALLY_ENCRYPTED_DATA) ||
            (t == SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
}

bool can_have_partial_length (const uint8_t t) {
    return Partial::can_have_partial_length(t);
}

std::string Tag::show_title() const {
    static const std::map <HeaderFormat, std::string> HeaderFormatString = {
        std::make_pair(HeaderFormat::NEW, "New"),
        std::make_pair(HeaderFormat::OLD, "Old"),
    };

    return HeaderFormatString.at(header_format) + ": " + NAME.at(tag) + " (Tag " + std::to_string(tag) + ")";
}

std::string Tag::actual_write() const {
    const std::string data = raw();             // assume validity already checked
    if ((header_format == HeaderFormat::NEW) || // specified new header
        (tag > 15)) {                           // tag > 15, so new header is required
        return write_new_length(tag, data, Packet::NOT_PARTIAL);
    }
    return write_old_length(tag, data, Packet::NOT_PARTIAL);
}

Tag::Tag(const uint8_t t)
    : Tag(t, 0)
{}

Tag::Tag(const uint8_t t, uint8_t ver)
    : tag(t),
      version(ver),
      header_format(HeaderFormat::NEW),
      size(0)
{}

Tag::Tag()
    : Tag(UNKNOWN)
{}

Tag::~Tag() {}

void Tag::read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length, const bool check_end) {
    // set size first, in case the size variable is needed during actual_read
    // the size won't change during actual_read, so there is no need to reset it after
    set_size(length);
    if (size) {
        const std::string::size_type orig_pos = pos;
        actual_read(data, pos, length);
        if (check_end && (pos != (orig_pos + length))) {
            throw std::runtime_error("Bad read of Tag " + std::to_string(tag) + ": offset " + std::to_string(orig_pos) + " + " + std::to_string(length) + " octets; now at " + std::to_string(pos));
        }
    }
}

void Tag::read(const std::string & data, const bool check_end) {
    std::string::size_type pos = 0;
    read(data, pos, data.size(), check_end);
}

void Tag::show(HumanReadable & hr) const {
    hr << show_title() << HumanReadable::DOWN;
    show_contents(hr);
    hr << HumanReadable::UP;
}

std::string Tag::show(const std::size_t indents, const std::size_t indent_size) const {
    HumanReadable hr(indent_size, indents);
    show(hr);
    return hr.get();
}

std::string Tag::raw(Status * status, const bool check_mpi) const {
    if (status && ((*status = valid(check_mpi)) != Status::SUCCESS)) {
        return "";
    }

    return actual_raw();
}

std::string Tag::write(Status * status, const bool check_mpi) const {
    if (status && ((*status = valid(check_mpi)) != Status::SUCCESS)) {
        return "";
    }

    return actual_write();
}

Status Tag::valid(const bool check_mpi) const {
    return actual_valid(check_mpi);
}

uint8_t Tag::get_tag() const {
    return tag;
}

Packet::HeaderFormat Tag::get_header_format() const {
    return header_format;
}

uint8_t Tag::get_version() const {
    return version;
}

std::size_t Tag::get_size() const {
    return size;
}

void Tag::set_tag(const uint8_t t) {
    tag = t;
}

void Tag::set_header_format(const HeaderFormat hf) {
    header_format = hf;
}

void Tag::set_version(const uint8_t v) {
    version = v;
}

void Tag::set_size(const std::size_t s) {
    size = s;
}

}
}

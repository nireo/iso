#ifndef __ISO_H__
#define __ISO_H__

#include "entry.pb.h"
#include <leveldb/db.h>
#include <memory>

class ISO {
public:
  void WriteEntry(const Entry &entry);

private:
  std::unique_ptr<leveldb::DB> store_;
};

#endif

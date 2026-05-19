#pragma once

#include <vector>
#include <map>
#include <unordered_map>
#include <vector>
#include "Task.h"

namespace libcron
{           
    template<typename LockType>
    class TaskQueue
    {
        public:
            const std::vector<Task>& get_tasks() const
            {
                return c;
            }
            
            std::vector<Task>& get_tasks()
            {
                return c;
            }
            
            size_t size() const noexcept
            {
                return c.size();
            }
            
            bool empty() const noexcept
            {
                return c.empty();
            }
            
            void push(Task& t)
            {
                c.push_back(std::move(t));
            }
            
            void push(Task&& t)
            {
                c.push_back(std::move(t));
            }
            
            void push(std::vector<Task>& tasks_to_insert)
            {
                c.reserve(c.size() + tasks_to_insert.size());
                c.insert(c.end(), std::make_move_iterator(tasks_to_insert.begin()), std::make_move_iterator(tasks_to_insert.end()));
            }
            
            const Task& top() const
            {
                return c[0];
            }
            
            Task& at(const size_t i)
            {
                return c[i];
            }
            
            void sort()
            {
                std::sort(c.begin(), c.end(), std::less<>());
            }
            
            void clear()
            {
                lock.lock();
                c.clear();
                lock.unlock();
            }
            
            void remove(Task& to_remove)
            {
                auto it = std::find_if(c.begin(), c.end(), [&to_remove] (const Task& to_compare) { 
                                    return to_remove.get_name() == to_compare;
                                    });
                
                if (it != c.end())
                {
                    c.erase(it);
                }
            }

            void remove(std::string to_remove)
            {
                lock.lock();
                auto it = std::find_if(c.begin(), c.end(), [&to_remove] (const Task& to_compare) { 
                                    return to_remove == to_compare;
                                    });
                if (it != c.end())
                {
                    c.erase(it);
                } 
                
                lock.unlock();
            }
            
            void lock_queue()
            {
                /* Do not allow to manipulate the Queue */
                lock.lock();
            }
            
            void release_queue()
            {
                /* Allow Access to the Queue Manipulating-Functions */
                lock.unlock();
            }
            
        private:
            LockType lock;
            std::vector<Task> c;
    };
}

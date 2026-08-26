from dataclasses import dataclass
from threading import RLock


@dataclass(slots=True)
class UsernameNode:
    username: str
    normalized_username: str
    user_id: int
    next: "UsernameNode | None" = None


class UsernameLinkedList:
    """Thread-safe linked-list index used for username lookup and ordering."""

    def __init__(self):
        self.head = None
        self.tail = None
        self._size = 0
        self._lock = RLock()

    @staticmethod
    def normalize(username):
        return username.strip().casefold()

    def rebuild(self, accounts):
        with self._lock:
            self.head = None
            self.tail = None
            self._size = 0
            for account in accounts:
                self._append_unlocked(account.username, account.id)

    def _append_unlocked(self, username, user_id):
        normalized = self.normalize(username)
        node = UsernameNode(username, normalized, user_id)
        if self.tail is None:
            self.head = node
            self.tail = node
        else:
            self.tail.next = node
            self.tail = node
        self._size += 1
        return node

    def add(self, username, user_id):
        with self._lock:
            if self._find_unlocked(username) is not None:
                return False
            self._append_unlocked(username, user_id)
            return True

    def _find_unlocked(self, username):
        normalized = self.normalize(username)
        current = self.head
        while current is not None:
            if current.normalized_username == normalized:
                return current
            current = current.next
        return None

    def find(self, username):
        with self._lock:
            return self._find_unlocked(username)

    def contains(self, username):
        return self.find(username) is not None

    def remove(self, username):
        normalized = self.normalize(username)
        with self._lock:
            previous = None
            current = self.head
            while current is not None:
                if current.normalized_username == normalized:
                    if previous is None:
                        self.head = current.next
                    else:
                        previous.next = current.next
                    if current is self.tail:
                        self.tail = previous
                    self._size -= 1
                    return True
                previous = current
                current = current.next
            return False

    def prefix_search(self, prefix, limit=8):
        normalized_prefix = self.normalize(prefix)
        matches = []
        with self._lock:
            current = self.head
            while current is not None and len(matches) < limit:
                if current.normalized_username.startswith(normalized_prefix):
                    matches.append(
                        {"username": current.username, "user_id": current.user_id}
                    )
                current = current.next
        return matches

    def to_list(self):
        usernames = []
        with self._lock:
            current = self.head
            while current is not None:
                usernames.append(current.username)
                current = current.next
        return usernames

    def __len__(self):
        with self._lock:
            return self._size


username_index = UsernameLinkedList()

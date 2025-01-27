#!/usr/bin/env python
# coding: utf-8

# In[1]:


class BookCollection:
    def __init__(self):
        self.books = {}

    def add_book(self, title, author, year, genre):
        if title in self.books:
            print(f"Error: '{title}' already exists in the collection.")
        else:
            self.books[title] = {
                'author': author,
                'year': year,
                'genre': genre
            }
            print(f"Book '{title}' added successfully.")

    def search_by_author(self, author):
        found_books = [title for title, details in self.books.items() if details['author'].lower() == author.lower()]
        if found_books:
            print(f"Books by {author}: {', '.join(found_books)}")
        else:
            print(f"No books found by author '{author}'.")

    def search_by_genre(self, genre):
        found_books = [title for title, details in self.books.items() if details['genre'].lower() == genre.lower()]
        if found_books:
            print(f"Books in genre '{genre}': {', '.join(found_books)}")
        else:
            print(f"No books found in genre '{genre}'.")

    def update_book(self, title, author=None, year=None, genre=None):
        if title in self.books:
            if author:
                self.books[title]['author'] = author
            if year:
                self.books[title]['year'] = year
            if genre:
                self.books[title]['genre'] = genre
            print(f"Book '{title}' updated successfully.")
        else:
            print(f"Error: '{title}' not found in the collection.")

    def delete_book(self, title):
        if title in self.books:
            del self.books[title]
            print(f"Book '{title}' deleted successfully.")
        else:
            print(f"Error: '{title}' not found in the collection.")

    def display_books(self):
        if not self.books:
            print("No books in the collection.")
        else:
            for title, details in self.books.items():
                print(f"Title: {title}, Author: {details['author']}, Year: {details['year']}, Genre: {details['genre']}")

# Example usage
collection = BookCollection()

# Adding books
collection.add_book("The Great Gatsby", "F. Scott Fitzgerald", 1925, "Fiction")
collection.add_book("To Kill a Mockingbird", "Harper Lee", 1960, "Fiction")
collection.add_book("1984", "George Orwell", 1949, "Dystopian")

# Searching by author
collection.search_by_author("George Orwell")

# Searching by genre
collection.search_by_genre("Fiction")

# Updating a book
collection.update_book("1984", year=1950)

# Displaying all books
collection.display_books()

# Deleting a book
collection.delete_book("The Great Gatsby")

# Displaying all books after deletion
collection.display_books()


# In[ ]:





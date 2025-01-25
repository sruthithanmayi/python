#!/usr/bin/env python
# coding: utf-8

# In[1]:


import matplotlib.pyplot as plt
import numpy as np

# Sample data
data = np.random.normal(0, 1, 1000)  # Generate 1000 random numbers from a normal distribution

# Create the histogram
plt.hist(data, bins=30, color='blue', edgecolor='black', alpha=0.7)

# Add labels and title
plt.title('Histogram Example')
plt.xlabel('Value')
plt.ylabel('Frequency')

# Show the plot
plt.show()


# In[ ]:





import networkx as nx
import matplotlib.pyplot as plt 


class CallGraph(nx.DiGraph):
    def render_as_image(self):
        nx.draw(self, with_labels=True)
        plt.show()
    
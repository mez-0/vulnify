from __future__ import annotations

from dataclasses import dataclass, field

from vulnify.constants import ProductType


@dataclass(slots=True)
class Vendor:
    """
    Vendor model represents a vendor.
    """
    
    """
    Name model represents a name.
    """
    name: str = field(default_factory=str)
    """
    Website model represents a website.
    """
    website: str = field(default_factory=str)
    
    """
    Country model represents a country.
    """
    country: str = field(default_factory=str)
    
    """
    Aliases model represents a list of aliases.
    """
    aliases: list[str] = field(default_factory=list)
    """
    Products model represents a list of products.
    """
    products: list[Product] = field(default_factory=list)


@dataclass(slots=True)
class Product:
    name: str
    vendor: Vendor = field(default_factory=Vendor)
    
    """
    Product type model represents a product type.
    """
    product_type: ProductType = field(default=ProductType.UNKNOWN)
    
    """
    Family model represents a family.
    """
    family: str = field(default_factory=str)
    
    """
    Component model represents a component.
    """
    component: str = field(default_factory=str)
    
    """
    Aliases model represents a list of aliases.
    """
    aliases: list[str] = field(default_factory=list)

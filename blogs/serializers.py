from rest_framework import serializers
from .models import BlogPost, BlogComment, FollowUs
from django.utils.html import strip_tags  # To strip HTML tags


class BlogPostSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.name', read_only=True)  # Include creator's name
    tags = serializers.StringRelatedField(many=True)  # Serialize tags as their names
    bulleted_points = serializers.StringRelatedField(many=True)
    content = serializers.SerializerMethodField()


    class Meta:
        model = BlogPost
        fields = [
            'id', 'title', 'description', 'content', 'image', 'category', 
            'created_at', 'updated_at', 'slug', 'created_by_name', 'tags', 'bulleted_points',
        ]
    def get_content(self, obj):
        # This method strips out the HTML tags
        return strip_tags(obj.content)

class BlogCommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlogComment
        fields = ['id', 'name', 'email', 'topic', 'comment', 'created_at', 'is_approved', 'blog']

class FollowUsSerializer(serializers.ModelSerializer):
    class Meta:
        model = FollowUs
        fields = ['facebook', 'instagram', 'telegram', 'twitter', 'pinterest']
